/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * MongoDB Connection Manager with Resilient Pooling, Auto-Indexing & Health Monitoring
 */
import { MongoClient, Db, MongoClientOptions } from 'mongodb';
import { MongoHealthStatus } from './types';
import { logger } from '../../logger';

class MongoConnectionManager {
  private client: MongoClient | null = null;
  private db: Db | null = null;
  private isConnecting: boolean = false;
  private connectionPromise: Promise<Db | null> | null = null;
  private lastHealthCheck: MongoHealthStatus | null = null;
  private lastHealthCheckTime: number = 0;
  private indexesCreated: boolean = false;

  /**
   * Retrieves the configured MongoDB URI.
   * Connection string is strictly read from environment variables to safeguard credentials.
   */
  public getUri(): string | undefined {
    return process.env.MONGODB_URI;
  }

  /**
   * Retrieves the target database name.
   */
  public getDbName(): string {
    return process.env.MONGODB_DB_NAME || 'cyber_threat_detection';
  }

  /**
   * Returns a safely masked URI for logging (passwords replaced with asterisks).
   */
  public getMaskedUri(): string {
    const rawUri = this.getUri();
    if (!rawUri) return 'UNCONFIGURED';
    try {
      return rawUri.replace(/(mongodb(?:\+srv)?:\/\/[^:]+:)([^@]+)@/i, '$1***:***@');
    } catch {
      return 'MASKED_URI';
    }
  }

  /**
   * Checks if MongoDB environment configuration is present.
   */
  public isConfigured(): boolean {
    const uri = this.getUri();
    return Boolean(uri && uri.trim().length > 0);
  }

  /**
   * Lazily initializes and returns the MongoDB database instance.
   * If not configured or unreachable, returns null without crashing the process.
   */
  public async getDatabase(): Promise<Db | null> {
    if (this.db) {
      return this.db;
    }

    if (!this.isConfigured()) {
      return null;
    }

    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    this.connectionPromise = this.connect();
    return this.connectionPromise;
  }

  /**
   * Establishes the MongoClient connection with robust options.
   */
  private async connect(): Promise<Db | null> {
    const uri = this.getUri();
    if (!uri) {
      return null;
    }

    this.isConnecting = true;
    try {
      const options: MongoClientOptions = {
        maxPoolSize: 20,
        minPoolSize: 2,
        maxIdleTimeMS: 30000,
        connectTimeoutMS: 5000,
        serverSelectionTimeoutMS: 5000,
        retryWrites: true,
        w: 'majority'
      };

      this.client = new MongoClient(uri, options);
      await this.client.connect();

      const dbName = this.getDbName();
      this.db = this.client.db(dbName);

      logger.info(`[MongoDB] Successfully connected to database: ${dbName} (${this.getMaskedUri()})`);

      // Initialize necessary indexes on background
      this.ensureIndexes(this.db).catch((err) => {
        logger.warn(`[MongoDB] Warning creating indexes: ${err.message}`);
      });

      return this.db;
    } catch (err: any) {
      logger.warn(`[MongoDB] Connection failed (${this.getMaskedUri()}): ${err.message}`);
      this.db = null;
      if (this.client) {
        try {
          await this.client.close();
        } catch {
          // ignore
        }
        this.client = null;
      }
      return null;
    } finally {
      this.isConnecting = false;
      this.connectionPromise = null;
    }
  }

  /**
   * Creates indexes for high-throughput queries:
   * Timestamps, severity, status, event contentHash, and incident identifiers.
   */
  public async ensureIndexes(db: Db): Promise<void> {
    if (this.indexesCreated) return;

    try {
      // 1. Security Events Indexes
      const eventsCol = db.collection('security_events');
      await eventsCol.createIndex({ id: 1 }, { unique: true, sparse: true });
      await eventsCol.createIndex({ contentHash: 1 });
      await eventsCol.createIndex({ timestamp: -1 });
      await eventsCol.createIndex({ severity: 1, timestamp: -1 });
      await eventsCol.createIndex({ source: 1, eventType: 1 });
      await eventsCol.createIndex({ sourceIp: 1 });
      await eventsCol.createIndex({ host: 1 });

      // 2. Incidents Indexes
      const incidentsCol = db.collection('incidents');
      await incidentsCol.createIndex({ incidentId: 1 }, { unique: true });
      await incidentsCol.createIndex({ status: 1, severity: 1 });
      await incidentsCol.createIndex({ priority: 1 });
      await incidentsCol.createIndex({ riskScore: -1 });
      await incidentsCol.createIndex({ createdAt: -1 });
      await incidentsCol.createIndex({ updatedAt: -1 });

      // 3. Threat Detections Indexes
      const detectionsCol = db.collection('threat_detections');
      await detectionsCol.createIndex({ detectionId: 1 }, { unique: true });
      await detectionsCol.createIndex({ eventId: 1 });
      await detectionsCol.createIndex({ severity: 1, timestamp: -1 });
      await detectionsCol.createIndex({ threatType: 1 });
      await detectionsCol.createIndex({ detectionEngine: 1 });

      // 4. Alerts Indexes
      const alertsCol = db.collection('alerts');
      await alertsCol.createIndex({ alertId: 1 }, { unique: true });
      await alertsCol.createIndex({ incidentId: 1 });
      await alertsCol.createIndex({ status: 1, priority: 1 });
      await alertsCol.createIndex({ severity: 1 });
      await alertsCol.createIndex({ timestamp: -1 });

      // 5. Agent Logs Indexes
      const agentLogsCol = db.collection('agent_logs');
      await agentLogsCol.createIndex({ logId: 1 }, { unique: true });
      await agentLogsCol.createIndex({ agentId: 1, timestamp: -1 });
      await agentLogsCol.createIndex({ level: 1 });
      await agentLogsCol.createIndex({ timestamp: -1 });

      // 6. Model Metadata Indexes
      const modelsCol = db.collection('model_metadata');
      await modelsCol.createIndex({ modelId: 1 }, { unique: true });
      await modelsCol.createIndex({ status: 1 });
      await modelsCol.createIndex({ algorithm: 1 });
      await modelsCol.createIndex({ trainedAt: -1 });

      this.indexesCreated = true;
      logger.info('[MongoDB] Verified collection indexes (events, incidents, detections, alerts, logs, models)');
    } catch (err: any) {
      logger.warn(`[MongoDB] Error configuring indexes: ${err.message}`);
    }
  }

  /**
   * Health check for MongoDB connection and collection metrics.
   */
  public async checkHealth(): Promise<MongoHealthStatus> {
    const now = Date.now();
    // Cache health for 2 seconds to prevent spamming the database
    if (this.lastHealthCheck && now - this.lastHealthCheckTime < 2000) {
      return this.lastHealthCheck;
    }

    if (!this.isConfigured()) {
      const res: MongoHealthStatus = {
        status: 'UNCONFIGURED',
        connected: false,
        details: 'MONGODB_URI environment variable is not set. Using secure local fallback store.'
      };
      this.lastHealthCheck = res;
      this.lastHealthCheckTime = now;
      return res;
    }

    try {
      const db = await this.getDatabase();
      if (!db) {
        const res: MongoHealthStatus = {
          status: 'DISCONNECTED',
          connected: false,
          database: this.getDbName(),
          host: this.getMaskedUri(),
          details: 'Unable to connect to MongoDB server with current credentials/URI.'
        };
        this.lastHealthCheck = res;
        this.lastHealthCheckTime = now;
        return res;
      }

      // Ping the server to verify active connection
      await db.command({ ping: 1 });

      const [eventsCount, incidentsCount, detectionsCount, alertsCount, logsCount, modelsCount] = await Promise.all([
        db.collection('security_events').estimatedDocumentCount().catch(() => 0),
        db.collection('incidents').estimatedDocumentCount().catch(() => 0),
        db.collection('threat_detections').estimatedDocumentCount().catch(() => 0),
        db.collection('alerts').estimatedDocumentCount().catch(() => 0),
        db.collection('agent_logs').estimatedDocumentCount().catch(() => 0),
        db.collection('model_metadata').estimatedDocumentCount().catch(() => 0)
      ]);

      const res: MongoHealthStatus = {
        status: 'CONNECTED',
        connected: true,
        database: this.getDbName(),
        host: this.getMaskedUri(),
        collections: {
          securityEvents: eventsCount,
          incidents: incidentsCount,
          threatDetections: detectionsCount,
          alerts: alertsCount,
          agentLogs: logsCount,
          modelMetadata: modelsCount
        }
      };

      this.lastHealthCheck = res;
      this.lastHealthCheckTime = now;
      return res;
    } catch (err: any) {
      const res: MongoHealthStatus = {
        status: 'ERROR',
        connected: false,
        database: this.getDbName(),
        host: this.getMaskedUri(),
        details: err.message
      };
      this.lastHealthCheck = res;
      this.lastHealthCheckTime = now;
      return res;
    }
  }

  /**
   * Graceful close of MongoDB client connections.
   */
  public async close(): Promise<void> {
    if (this.client) {
      try {
        await this.client.close();
      } catch {
        // ignore
      }
      this.client = null;
      this.db = null;
      this.indexesCreated = false;
      logger.info('[MongoDB] Connection closed.');
    }
  }
}

export const mongoConnection = new MongoConnectionManager();
