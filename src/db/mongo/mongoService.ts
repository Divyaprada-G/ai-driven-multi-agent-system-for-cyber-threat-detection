/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * MongoDB Service Layer implementing all CRUD, Aggregation, and Fallback Operations
 */
import { mongoConnection } from './connection';
import {
  validateSecurityEventInput,
  validateIncidentInput,
  validateThreatDetectionInput,
  validateAlertInput,
  validateAgentLogInput,
  validateModelMetadataInput
} from './validation';
import {
  MongoSecurityEvent,
  MongoIncident,
  MongoThreatDetection,
  MongoAlert,
  MongoAgentLog,
  MongoModelMetadata,
  MongoPaginationOptions,
  MongoPaginatedResult,
  MongoDashboardStats,
  IncidentStatus,
  AlertStatus,
  MongoRawEvent,
  MongoNormalizedEvent,
  MongoValidationResult,
  MongoAgentProcessingResult,
  MongoCorrelationRecord,
  MongoThreatDetectionRecord,
  MongoRiskScoreRecord,
  MongoAlertRecord,
  MongoIncidentRecord,
  MongoAuditLogRecord,
  PersistenceWriteResult,
  FullTelemetryPersistenceSummary
} from './types';
import { localStore } from '../localStore';
import { logger } from '../../logger';

class MongoService {
  private lastSuccessfulWrite: string | null = null;
  private persistenceFailures: number = 0;
  private lastPersistenceError: string | null = null;
  private totalPersistedRecords: number = 0;
  private retryAttemptsCount: number = 0;

  /**
   * Get current persistence health metrics
   */
  public getPersistenceMetrics() {
    return {
      lastSuccessfulWrite: this.lastSuccessfulWrite,
      persistenceFailures: this.persistenceFailures,
      lastPersistenceError: this.lastPersistenceError,
      totalPersistedRecords: this.totalPersistedRecords,
      retryAttemptsCount: this.retryAttemptsCount
    };
  }

  /**
   * Reset metrics (primarily for test harness)
   */
  public resetMetrics() {
    this.persistenceFailures = 0;
    this.lastPersistenceError = null;
    this.totalPersistedRecords = 0;
    this.retryAttemptsCount = 0;
  }

  /**
   * Safe retry helper with exponential backoff
   */
  private async executeWithRetry<T>(
    operationName: string,
    operation: () => Promise<T>,
    maxRetries: number = 2
  ): Promise<T> {
    let attempt = 0;
    let delay = 100;

    while (attempt <= maxRetries) {
      try {
        return await operation();
      } catch (err: any) {
        attempt++;
        // Do not retry on duplicate key errors (code 11000)
        if (err.code === 11000 || err.message?.includes('duplicate key')) {
          throw err;
        }
        if (attempt > maxRetries) {
          logger.warn(`[MongoService] ${operationName} failed after ${maxRetries + 1} attempts: ${err.message}`);
          throw err;
        }
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= 2;
      }
    }
    throw new Error(`[MongoService] ${operationName} exceeded retry limit.`);
  }
  /**
   * Helper to normalize pagination parameters.
   */
  private normalizePagination(options?: MongoPaginationOptions) {
    const limit = Math.max(1, Math.min(500, Number(options?.limit || 50)));
    const offset = Math.max(0, Number(options?.offset ?? ((Number(options?.page || 1) - 1) * limit)));
    const page = Math.floor(offset / limit) + 1;
    const sortBy = options?.sortBy || 'timestamp';
    const sortOrder: 1 | -1 = options?.sortOrder === 'asc' ? 1 : -1;

    return { limit, offset, page, sortBy, sortOrder };
  }

  // ============================================================================
  // 1. SECURITY EVENTS OPERATIONS
  // ============================================================================

  /**
   * Create a security event in MongoDB.
   * Handles deduplication by contentHash.
   */
  public async createSecurityEvent(rawInput: any): Promise<{ event: MongoSecurityEvent; isDuplicate: boolean }> {
    const validated = validateSecurityEventInput(rawInput);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      // Graceful fallback to local store if MongoDB is offline or unconfigured
      const existing = localStore.findRawEventByHash(validated.contentHash);
      if (existing) {
        return {
          event: {
            ...validated,
            id: existing.id || String(existing._id),
            _id: existing.id || existing._id
          },
          isDuplicate: true
        };
      }
      const localRec = localStore.insertRawEvent({
        ...validated,
        rawPayload: validated.rawPayload,
        normalizedFields: validated.normalizedFields
      });
      return {
        event: {
          ...validated,
          id: localRec.id,
          _id: localRec.id
        },
        isDuplicate: false
      };
    }

    try {
      const col = db.collection<MongoSecurityEvent>('security_events');

      // Deduplication check within last 24 hours
      const existing = await col.findOne({ contentHash: validated.contentHash });
      if (existing) {
        return {
          event: {
            ...existing,
            id: existing.id || String(existing._id)
          },
          isDuplicate: true
        };
      }

      const insertResult = await col.insertOne(validated as any);
      const created: MongoSecurityEvent = {
        ...validated,
        id: validated.id || String(insertResult.insertedId),
        _id: insertResult.insertedId
      };

      return { event: created, isDuplicate: false };
    } catch (err: any) {
      logger.warn(`[MongoService] createSecurityEvent failed, falling back to localStore: ${err.message}`);
      const existing = localStore.findRawEventByHash(validated.contentHash);
      if (existing) {
        return {
          event: {
            ...validated,
            id: existing.id || String(existing._id),
            _id: existing.id || existing._id
          },
          isDuplicate: true
        };
      }
      const localRec = localStore.insertRawEvent({
        ...validated,
        rawPayload: validated.rawPayload,
        normalizedFields: validated.normalizedFields
      });
      return {
        event: { ...validated, id: localRec.id, _id: localRec.id },
        isDuplicate: false
      };
    }
  }

  /**
   * Retrieve security events with filtering and pagination.
   */
  public async getSecurityEvents(
    filters: {
      severity?: string;
      source?: string;
      eventType?: string;
      sourceIp?: string;
      host?: string;
      search?: string;
      startTime?: string | Date;
      endTime?: string | Date;
    } = {},
    pagination?: MongoPaginationOptions
  ): Promise<MongoPaginatedResult<MongoSecurityEvent>> {
    const { limit, offset, page, sortBy, sortOrder } = this.normalizePagination(pagination);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const localEvents = localStore.listEvents(limit * 4);
      let filtered = localEvents;

      if (filters.severity) {
        filtered = filtered.filter((e) => e.severity?.toUpperCase() === filters.severity?.toUpperCase());
      }
      if (filters.source) {
        filtered = filtered.filter((e) => e.source?.toLowerCase().includes(filters.source!.toLowerCase()));
      }
      if (filters.sourceIp) {
        filtered = filtered.filter((e) => e.sourceIp === filters.sourceIp);
      }
      if (filters.search) {
        const q = filters.search.toLowerCase();
        filtered = filtered.filter(
          (e) =>
            e.source?.toLowerCase().includes(q) ||
            e.eventType?.toLowerCase().includes(q) ||
            e.rawPayload?.toLowerCase().includes(q) ||
            e.host?.toLowerCase().includes(q)
        );
      }

      const total = filtered.length;
      const sliced = filtered.slice(offset, offset + limit).map((e: any) => ({
        id: e.id,
        source: e.source,
        eventType: e.eventType,
        severity: e.severity || 'MEDIUM',
        rawPayload: e.rawPayload,
        normalizedFields: e.normalizedFields || {},
        sourceIp: e.sourceIp,
        destinationIp: e.destinationIp,
        host: e.host,
        username: e.username,
        contentHash: e.contentHash || '',
        batchId: e.batchId,
        isTestEvent: e.isTestEvent,
        timestamp: new Date(e.eventTimestamp || e.timestamp || Date.now()),
        createdAt: new Date(e.createdAt || Date.now())
      }));

      return {
        data: sliced,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    }

    try {
      const col = db.collection<MongoSecurityEvent>('security_events');
      const query: Record<string, any> = {};

      if (filters.severity) {
        query.severity = filters.severity.toUpperCase();
      }
      if (filters.source) {
        query.source = { $regex: filters.source, $options: 'i' };
      }
      if (filters.eventType) {
        query.eventType = { $regex: filters.eventType, $options: 'i' };
      }
      if (filters.sourceIp) {
        query.sourceIp = filters.sourceIp;
      }
      if (filters.host) {
        query.host = { $regex: filters.host, $options: 'i' };
      }
      if (filters.startTime || filters.endTime) {
        query.timestamp = {};
        if (filters.startTime) query.timestamp.$gte = new Date(filters.startTime);
        if (filters.endTime) query.timestamp.$lte = new Date(filters.endTime);
      }
      if (filters.search) {
        query.$or = [
          { source: { $regex: filters.search, $options: 'i' } },
          { eventType: { $regex: filters.search, $options: 'i' } },
          { rawPayload: { $regex: filters.search, $options: 'i' } },
          { host: { $regex: filters.search, $options: 'i' } },
          { sourceIp: { $regex: filters.search, $options: 'i' } }
        ];
      }

      const sortField = sortBy === 'severity' ? 'severity' : sortBy === 'source' ? 'source' : 'timestamp';
      const [data, total] = await Promise.all([
        col
          .find(query)
          .sort({ [sortField]: sortOrder })
          .skip(offset)
          .limit(limit)
          .toArray(),
        col.countDocuments(query)
      ]);

      return {
        data,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    } catch (err: any) {
      logger.warn(`[MongoService] getSecurityEvents failed: ${err.message}`);
      throw err;
    }
  }

  /**
   * Retrieve a single security event by its identifier.
   */
  public async getSecurityEventById(id: string): Promise<MongoSecurityEvent | null> {
    const db = await mongoConnection.getDatabase();
    if (!db) {
      const e = localStore.getEventById(id);
      if (!e) return null;
      return {
        id: e.id,
        source: e.source,
        eventType: e.eventType,
        severity: e.severity || 'MEDIUM',
        rawPayload: e.rawPayload,
        normalizedFields: e.normalizedFields || {},
        sourceIp: e.sourceIp,
        destinationIp: e.destinationIp,
        host: e.host,
        username: e.username,
        contentHash: e.contentHash || '',
        batchId: e.batchId,
        isTestEvent: e.isTestEvent,
        timestamp: new Date(e.eventTimestamp || Date.now()),
        createdAt: new Date(e.createdAt || Date.now())
      };
    }

    try {
      const col = db.collection<MongoSecurityEvent>('security_events');
      return await col.findOne({ id });
    } catch (err: any) {
      logger.warn(`[MongoService] getSecurityEventById failed: ${err.message}`);
      return null;
    }
  }

  // ============================================================================
  // 2. CORRELATED INCIDENTS OPERATIONS
  // ============================================================================

  /**
   * Create an incident record in MongoDB.
   */
  public async createIncident(rawInput: any): Promise<MongoIncident> {
    const validated = validateIncidentInput(rawInput);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const localInc = localStore.insertIncident({
        incidentId: validated.incidentId,
        title: validated.title,
        description: validated.description,
        severity: validated.severity,
        priority: validated.priority,
        status: validated.status,
        riskScore: validated.riskScore,
        primaryIp: validated.primaryIp,
        affectedHost: validated.affectedHost,
        mitreTechniques: validated.mitreTechniques,
        investigationNotes: validated.investigationNotes
      });
      return {
        ...validated,
        _id: localInc.id
      };
    }

    try {
      const col = db.collection<MongoIncident>('incidents');
      const insertResult = await col.insertOne(validated as any);
      return {
        ...validated,
        _id: insertResult.insertedId
      };
    } catch (err: any) {
      logger.warn(`[MongoService] createIncident failed, falling back to localStore: ${err.message}`);
      const localInc = localStore.insertIncident({
        incidentId: validated.incidentId,
        title: validated.title,
        description: validated.description,
        severity: validated.severity,
        priority: validated.priority,
        status: validated.status,
        riskScore: validated.riskScore,
        primaryIp: validated.primaryIp,
        affectedHost: validated.affectedHost,
        mitreTechniques: validated.mitreTechniques,
        investigationNotes: validated.investigationNotes
      });
      return {
        ...validated,
        _id: localInc.id
      };
    }
  }

  /**
   * Retrieve incidents with filtering, sorting and pagination.
   */
  public async getIncidents(
    filters: {
      status?: string;
      severity?: string;
      priority?: string;
      assignee?: string;
      search?: string;
      minRisk?: number;
      startTime?: string | Date;
      endTime?: string | Date;
      limit?: number;
      offset?: number;
      page?: number;
    } = {},
    pagination?: MongoPaginationOptions
  ): Promise<MongoPaginatedResult<MongoIncident>> {
    const effectivePagination = {
      limit: filters.limit,
      offset: filters.offset,
      page: filters.page,
      ...pagination
    };
    const { limit, offset, page, sortBy, sortOrder } = this.normalizePagination({
      ...effectivePagination,
      sortBy: effectivePagination?.sortBy || 'createdAt'
    });

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const localIncidents = localStore.listIncidents(limit * 4);
      let filtered = localIncidents;

      if (filters.status) {
        filtered = filtered.filter((i) => i.status?.toUpperCase() === filters.status?.toUpperCase());
      }
      if (filters.severity) {
        filtered = filtered.filter((i) => i.severity?.toUpperCase() === filters.severity?.toUpperCase());
      }
      if (filters.priority) {
        filtered = filtered.filter((i) => i.priority?.toUpperCase() === filters.priority?.toUpperCase());
      }
      if (filters.minRisk !== undefined) {
        filtered = filtered.filter((i) => Number(i.riskScore || 0) >= filters.minRisk!);
      }
      if (filters.search) {
        const q = filters.search.toLowerCase();
        filtered = filtered.filter(
          (i) =>
            i.title?.toLowerCase().includes(q) ||
            i.description?.toLowerCase().includes(q) ||
            i.incidentId?.toLowerCase().includes(q) ||
            i.primaryIp?.toLowerCase().includes(q) ||
            i.affectedHost?.toLowerCase().includes(q)
        );
      }

      const total = filtered.length;
      const sliced = filtered.slice(offset, offset + limit).map((i: any) => ({
        incidentId: i.incidentId || i.id,
        title: i.title,
        description: i.description || '',
        severity: i.severity || 'HIGH',
        priority: i.priority || 'P2',
        status: i.status || 'NEW',
        riskScore: i.riskScore || 50,
        primaryIp: i.primaryIp,
        affectedHost: i.affectedHost,
        mitreTechniques: i.mitreTechniques || [],
        correlatedEvents: i.correlatedEvents || [],
        investigationNotes: i.investigationNotes || [],
        containmentStatus: i.containmentStatus || 'UNCONTAINED',
        assignee: i.assignee,
        resolutionSummary: i.resolutionSummary,
        createdAt: new Date(i.createdAt || Date.now()),
        updatedAt: new Date(i.updatedAt || Date.now())
      }));

      return {
        data: sliced,
        incidents: sliced,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    }

    try {
      const col = db.collection<MongoIncident>('incidents');
      const query: Record<string, any> = {};

      if (filters.status) {
        query.status = filters.status.toUpperCase();
      }
      if (filters.severity) {
        query.severity = filters.severity.toUpperCase();
      }
      if (filters.priority) {
        query.priority = filters.priority.toUpperCase();
      }
      if (filters.assignee) {
        query.assignee = { $regex: filters.assignee, $options: 'i' };
      }
      if (filters.minRisk !== undefined) {
        query.riskScore = { $gte: Number(filters.minRisk) };
      }
      if (filters.startTime || filters.endTime) {
        query.createdAt = {};
        if (filters.startTime) query.createdAt.$gte = new Date(filters.startTime);
        if (filters.endTime) query.createdAt.$lte = new Date(filters.endTime);
      }
      if (filters.search) {
        query.$or = [
          { incidentId: { $regex: filters.search, $options: 'i' } },
          { title: { $regex: filters.search, $options: 'i' } },
          { description: { $regex: filters.search, $options: 'i' } },
          { primaryIp: { $regex: filters.search, $options: 'i' } },
          { affectedHost: { $regex: filters.search, $options: 'i' } }
        ];
      }

      const sortField =
        sortBy === 'riskScore'
          ? 'riskScore'
          : sortBy === 'severity'
          ? 'severity'
          : sortBy === 'updatedAt'
          ? 'updatedAt'
          : 'createdAt';

      const [data, total] = await Promise.all([
        col
          .find(query)
          .sort({ [sortField]: sortOrder })
          .skip(offset)
          .limit(limit)
          .toArray(),
        col.countDocuments(query)
      ]);

      return {
        data,
        incidents: data,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    } catch (err: any) {
      logger.warn(`[MongoService] getIncidents failed: ${err.message}`);
      throw err;
    }
  }

  /**
   * Retrieve an incident by its incidentId.
   */
  public async getIncidentById(incidentId: string): Promise<MongoIncident | null> {
    const db = await mongoConnection.getDatabase();
    if (!db) {
      const inc = localStore.getIncidentById(incidentId);
      if (!inc) return null;
      return {
        incidentId: inc.incidentId || inc.id,
        title: inc.title,
        description: inc.description || '',
        severity: inc.severity || 'HIGH',
        priority: inc.priority || 'P2',
        status: inc.status || 'NEW',
        riskScore: inc.riskScore || 50,
        primaryIp: inc.primaryIp,
        affectedHost: inc.affectedHost,
        mitreTechniques: inc.mitreTechniques || [],
        correlatedEvents: inc.correlatedEvents || [],
        investigationNotes: inc.investigationNotes || [],
        containmentStatus: inc.containmentStatus || 'UNCONTAINED',
        assignee: inc.assignee,
        resolutionSummary: inc.resolutionSummary,
        createdAt: new Date(inc.createdAt || Date.now()),
        updatedAt: new Date(inc.updatedAt || Date.now())
      };
    }

    try {
      const col = db.collection<MongoIncident>('incidents');
      return await col.findOne({ incidentId });
    } catch (err: any) {
      logger.warn(`[MongoService] getIncidentById failed: ${err.message}`);
      return null;
    }
  }

  /**
   * Update incident status with audit tracking.
   */
  public async updateIncidentStatus(
    incidentId: string,
    status: IncidentStatus,
    actor: string = 'SOC Analyst',
    reason?: string
  ): Promise<MongoIncident | null> {
    const validStatus = status.toUpperCase() as IncidentStatus;

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const updated = localStore.updateIncidentStatus(incidentId, validStatus);
      if (!updated) return null;
      return this.getIncidentById(incidentId);
    }

    try {
      const col = db.collection<MongoIncident>('incidents');
      const existing = await col.findOne({ incidentId });
      if (!existing) return null;

      const historyEntry = {
        id: `hist-${Date.now()}`,
        field: 'status',
        oldValue: existing.status,
        newValue: validStatus,
        actor,
        reason: reason || 'Incident status updated via SOC Workflow',
        timestamp: new Date().toISOString()
      };

      const result = await col.findOneAndUpdate(
        { incidentId },
        {
          $set: {
            status: validStatus,
            updatedAt: new Date(),
            ...(validStatus === 'RESOLVED' ? { resolutionSummary: reason || 'Resolved by SOC Analyst' } : {})
          },
          $push: {
            investigationNotes: {
              id: `note-${Date.now()}`,
              author: actor,
              note: `Status changed from ${existing.status} to ${validStatus}.${reason ? ` Reason: ${reason}` : ''}`,
              timestamp: new Date().toISOString()
            }
          }
        } as any,
        { returnDocument: 'after' }
      );

      return (result as any)?.value || (await col.findOne({ incidentId }));
    } catch (err: any) {
      logger.warn(`[MongoService] updateIncidentStatus failed: ${err.message}`);
      throw err;
    }
  }

  /**
   * Add an investigation note to an existing incident.
   */
  public async addInvestigationNote(
    incidentId: string,
    noteText: string,
    author: string = 'SOC Analyst'
  ): Promise<MongoIncident | null> {
    if (!noteText || !noteText.trim()) {
      throw new Error('Note text cannot be empty.');
    }

    const note = {
      id: `note-${Date.now()}`,
      author: String(author || 'SOC Analyst').trim(),
      note: String(noteText).trim(),
      timestamp: new Date().toISOString()
    };

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const updated = localStore.addInvestigationNote(incidentId, note);
      if (!updated) return null;
      return this.getIncidentById(incidentId);
    }

    try {
      const col = db.collection<MongoIncident>('incidents');
      await col.updateOne(
        { incidentId },
        {
          $push: { investigationNotes: note },
          $set: { updatedAt: new Date() }
        } as any
      );

      return await col.findOne({ incidentId });
    } catch (err: any) {
      logger.warn(`[MongoService] addInvestigationNote failed: ${err.message}`);
      throw err;
    }
  }

  // ============================================================================
  // 3. THREAT DETECTIONS OPERATIONS
  // ============================================================================

  /**
   * Create a threat detection record in MongoDB.
   */
  public async createThreatDetection(rawInput: any): Promise<MongoThreatDetection> {
    const validated = validateThreatDetectionInput(rawInput);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      localStore.insertDetection({
        id: validated.detectionId,
        eventId: validated.eventId || 'EVT-LOCAL',
        modelId: validated.detectionEngine,
        modelVersion: '1.0.0',
        prediction: validated.threatType,
        predictedClass: validated.threatType,
        confidence: validated.confidence,
        classProbabilities: { [validated.threatType]: validated.confidence },
        featureSummary: validated.features,
        inferenceTimestamp: validated.timestamp.toISOString()
      });
      return { ...validated, _id: validated.detectionId };
    }

    try {
      const col = db.collection<MongoThreatDetection>('threat_detections');
      const insertResult = await col.insertOne(validated as any);
      return { ...validated, _id: insertResult.insertedId };
    } catch (err: any) {
      logger.warn(`[MongoService] createThreatDetection failed: ${err.message}`);
      return { ...validated, _id: validated.detectionId };
    }
  }

  /**
   * Retrieve threat detections with pagination and filtering.
   */
  public async getThreatDetections(
    filters: {
      threatType?: string;
      severity?: string;
      detectionEngine?: string;
      eventId?: string;
      startTime?: string | Date;
      endTime?: string | Date;
    } = {},
    pagination?: MongoPaginationOptions
  ): Promise<MongoPaginatedResult<MongoThreatDetection>> {
    const { limit, offset, page, sortBy, sortOrder } = this.normalizePagination(pagination);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const localDets = localStore.listDetections(limit * 2);
      const total = localDets.length;
      const sliced = localDets.slice(offset, offset + limit).map((d: any) => ({
        detectionId: d.id,
        eventId: d.eventId,
        threatType: d.predictedClass || d.prediction || 'Threat',
        threatCategory: 'CYBER_ATTACK',
        severity: (d.confidence > 0.85 ? 'CRITICAL' : d.confidence > 0.65 ? 'HIGH' : 'MEDIUM') as any,
        confidence: d.confidence || 0.8,
        detectionEngine: (d.modelId || 'RULE_BASED') as any,
        features: d.featureSummary || {},
        explanation: `Model detected ${d.predictedClass || 'threat'}`,
        timestamp: new Date(d.inferenceTimestamp || Date.now()),
        createdAt: new Date(d.createdAt || Date.now())
      }));

      return {
        data: sliced,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    }

    try {
      const col = db.collection<MongoThreatDetection>('threat_detections');
      const query: Record<string, any> = {};

      if (filters.threatType) {
        query.threatType = { $regex: filters.threatType, $options: 'i' };
      }
      if (filters.severity) {
        query.severity = filters.severity.toUpperCase();
      }
      if (filters.detectionEngine) {
        query.detectionEngine = filters.detectionEngine.toUpperCase();
      }
      if (filters.eventId) {
        query.eventId = filters.eventId;
      }
      if (filters.startTime || filters.endTime) {
        query.timestamp = {};
        if (filters.startTime) query.timestamp.$gte = new Date(filters.startTime);
        if (filters.endTime) query.timestamp.$lte = new Date(filters.endTime);
      }

      const sortField = sortBy === 'severity' ? 'severity' : sortBy === 'confidence' ? 'confidence' : 'timestamp';
      const [data, total] = await Promise.all([
        col
          .find(query)
          .sort({ [sortField]: sortOrder })
          .skip(offset)
          .limit(limit)
          .toArray(),
        col.countDocuments(query)
      ]);

      return {
        data,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    } catch (err: any) {
      logger.warn(`[MongoService] getThreatDetections failed: ${err.message}`);
      throw err;
    }
  }

  // ============================================================================
  // 4. ALERT RECORDS OPERATIONS
  // ============================================================================

  /**
   * Create an alert in MongoDB.
   */
  public async createAlert(rawInput: any): Promise<MongoAlert> {
    const validated = validateAlertInput(rawInput);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const localAlt = localStore.insertAlert({
        alertId: validated.alertId,
        incidentId: validated.incidentId,
        title: validated.title,
        description: validated.description,
        alertType: validated.alertType,
        severity: validated.severity,
        riskScore: validated.riskScore,
        priority: validated.priority,
        status: validated.status,
        mitreTechniques: validated.mitreTechniques,
        evidence: validated.evidence
      });
      return { ...validated, _id: localAlt.id };
    }

    try {
      const col = db.collection<MongoAlert>('alerts');
      const insertResult = await col.insertOne(validated as any);
      return { ...validated, _id: insertResult.insertedId };
    } catch (err: any) {
      logger.warn(`[MongoService] createAlert failed, falling back to localStore: ${err.message}`);
      const localAlt = localStore.insertAlert({
        alertId: validated.alertId,
        incidentId: validated.incidentId,
        title: validated.title,
        description: validated.description,
        alertType: validated.alertType,
        severity: validated.severity,
        riskScore: validated.riskScore,
        priority: validated.priority,
        status: validated.status,
        mitreTechniques: validated.mitreTechniques,
        evidence: validated.evidence
      });
      return { ...validated, _id: localAlt.id };
    }
  }

  /**
   * Retrieve alert history with filtering and pagination.
   */
  public async getAlerts(
    filters: {
      status?: string;
      severity?: string;
      priority?: string;
      incidentId?: string;
      alertType?: string;
      search?: string;
      startTime?: string | Date;
      endTime?: string | Date;
      limit?: number;
      offset?: number;
      page?: number;
    } = {},
    pagination?: MongoPaginationOptions
  ): Promise<MongoPaginatedResult<MongoAlert>> {
    const effectivePagination = {
      limit: filters.limit,
      offset: filters.offset,
      page: filters.page,
      ...pagination
    };
    const { limit, offset, page, sortBy, sortOrder } = this.normalizePagination(effectivePagination);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const localAlerts = localStore.listAlerts(limit * 4);
      let filtered = localAlerts;

      if (filters.status) {
        filtered = filtered.filter((a) => a.status?.toUpperCase() === filters.status?.toUpperCase());
      }
      if (filters.severity) {
        filtered = filtered.filter((a) => a.severity?.toUpperCase() === filters.severity?.toUpperCase());
      }
      if (filters.incidentId) {
        filtered = filtered.filter((a) => a.incidentId === filters.incidentId);
      }
      if (filters.search) {
        const q = filters.search.toLowerCase();
        filtered = filtered.filter(
          (a) =>
            a.title?.toLowerCase().includes(q) ||
            a.description?.toLowerCase().includes(q) ||
            a.alertId?.toLowerCase().includes(q)
        );
      }

      const total = filtered.length;
      const sliced = filtered.slice(offset, offset + limit).map((a: any) => ({
        alertId: a.alertId || a.id,
        incidentId: a.incidentId,
        title: a.title,
        description: a.description || '',
        alertType: a.alertType || 'SECURITY_ALERT',
        severity: a.severity || 'MEDIUM',
        riskScore: a.riskScore || 50,
        priority: a.priority || 'P3',
        status: a.status || 'NEW',
        mitreTechniques: a.mitreTechniques || [],
        evidence: a.evidence || [],
        actor: a.actor,
        timestamp: new Date(a.createdAt || Date.now()),
        createdAt: new Date(a.createdAt || Date.now()),
        updatedAt: new Date(a.updatedAt || Date.now())
      }));

      return {
        data: sliced,
        alerts: sliced,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    }

    try {
      const col = db.collection<MongoAlert>('alerts');
      const query: Record<string, any> = {};

      if (filters.status) {
        query.status = filters.status.toUpperCase();
      }
      if (filters.severity) {
        query.severity = filters.severity.toUpperCase();
      }
      if (filters.priority) {
        query.priority = filters.priority.toUpperCase();
      }
      if (filters.incidentId) {
        query.incidentId = filters.incidentId;
      }
      if (filters.alertType) {
        query.alertType = { $regex: filters.alertType, $options: 'i' };
      }
      if (filters.startTime || filters.endTime) {
        query.timestamp = {};
        if (filters.startTime) query.timestamp.$gte = new Date(filters.startTime);
        if (filters.endTime) query.timestamp.$lte = new Date(filters.endTime);
      }
      if (filters.search) {
        query.$or = [
          { alertId: { $regex: filters.search, $options: 'i' } },
          { title: { $regex: filters.search, $options: 'i' } },
          { description: { $regex: filters.search, $options: 'i' } }
        ];
      }

      const sortField = sortBy === 'severity' ? 'severity' : sortBy === 'riskScore' ? 'riskScore' : 'timestamp';
      const [data, total] = await Promise.all([
        col
          .find(query)
          .sort({ [sortField]: sortOrder })
          .skip(offset)
          .limit(limit)
          .toArray(),
        col.countDocuments(query)
      ]);

      return {
        data,
        alerts: data,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    } catch (err: any) {
      logger.warn(`[MongoService] getAlerts failed: ${err.message}`);
      throw err;
    }
  }

  /**
   * Update alert status.
   */
  public async updateAlertStatus(alertId: string, status: AlertStatus, actor: string = 'SOC Analyst'): Promise<MongoAlert | null> {
    const validStatus = status.toUpperCase() as AlertStatus;

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const updated = localStore.updateAlertStatus(alertId, validStatus);
      if (!updated) return null;
      return {
        alertId,
        title: updated.title,
        description: updated.description || '',
        alertType: updated.alertType || 'SECURITY_ALERT',
        severity: updated.severity || 'MEDIUM',
        riskScore: updated.riskScore || 50,
        priority: updated.priority || 'P3',
        status: validStatus,
        mitreTechniques: updated.mitreTechniques || [],
        evidence: updated.evidence || [],
        actor,
        timestamp: new Date(updated.createdAt || Date.now()),
        createdAt: new Date(updated.createdAt || Date.now()),
        updatedAt: new Date()
      };
    }

    try {
      const col = db.collection<MongoAlert>('alerts');
      const updated = await col.findOneAndUpdate(
        { alertId },
        {
          $set: {
            status: validStatus,
            actor,
            updatedAt: new Date()
          }
        },
        { returnDocument: 'after' }
      );
      return (updated as any)?.value || (await col.findOne({ alertId }));
    } catch (err: any) {
      logger.warn(`[MongoService] updateAlertStatus failed: ${err.message}`);
      throw err;
    }
  }

  // ============================================================================
  // 5. AGENT EXECUTION LOGS OPERATIONS
  // ============================================================================

  /**
   * Create an agent execution log.
   */
  public async createAgentLog(rawInput: any): Promise<MongoAgentLog> {
    const validated = validateAgentLogInput(rawInput);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      localStore.insertAuditLog({
        actor: validated.agentId,
        action: validated.action,
        targetType: 'AGENT_LOG',
        targetId: validated.logId,
        severity: validated.level === 'ERROR' ? 'HIGH' : 'LOW',
        details: {
          message: validated.message,
          executionTimeMs: validated.executionTimeMs,
          eventsProcessedCount: validated.eventsProcessedCount
        }
      });
      return { ...validated, _id: validated.logId };
    }

    try {
      const col = db.collection<MongoAgentLog>('agent_logs');
      const insertResult = await col.insertOne(validated as any);
      return { ...validated, _id: insertResult.insertedId };
    } catch (err: any) {
      logger.warn(`[MongoService] createAgentLog failed: ${err.message}`);
      return { ...validated, _id: validated.logId };
    }
  }

  /**
   * Retrieve agent execution logs with pagination and filtering.
   */
  public async getAgentLogs(
    filters: {
      agentId?: string;
      level?: string;
      action?: string;
      startTime?: string | Date;
      endTime?: string | Date;
    } = {},
    pagination?: MongoPaginationOptions
  ): Promise<MongoPaginatedResult<MongoAgentLog>> {
    const { limit, offset, page, sortOrder } = this.normalizePagination(pagination);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const audit = localStore.listAuditLogs(limit * 2);
      const total = audit.length;
      const sliced = audit.slice(offset, offset + limit).map((a: any) => ({
        logId: a.targetId || a.id,
        agentId: a.actor || 'Multi-Agent Coordinator',
        action: a.action || 'EXECUTE',
        level: (a.severity === 'HIGH' ? 'ERROR' : 'INFO') as any,
        message: a.details?.message || a.action,
        executionTimeMs: a.details?.executionTimeMs || 10,
        eventsProcessedCount: a.details?.eventsProcessedCount || 1,
        metadata: a.details,
        timestamp: new Date(a.timestamp || Date.now()),
        createdAt: new Date(a.timestamp || Date.now())
      }));

      return {
        data: sliced,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    }

    try {
      const col = db.collection<MongoAgentLog>('agent_logs');
      const query: Record<string, any> = {};

      if (filters.agentId) {
        query.agentId = { $regex: filters.agentId, $options: 'i' };
      }
      if (filters.level) {
        query.level = filters.level.toUpperCase();
      }
      if (filters.action) {
        query.action = { $regex: filters.action, $options: 'i' };
      }
      if (filters.startTime || filters.endTime) {
        query.timestamp = {};
        if (filters.startTime) query.timestamp.$gte = new Date(filters.startTime);
        if (filters.endTime) query.timestamp.$lte = new Date(filters.endTime);
      }

      const [data, total] = await Promise.all([
        col.find(query).sort({ timestamp: sortOrder }).skip(offset).limit(limit).toArray(),
        col.countDocuments(query)
      ]);

      return {
        data,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    } catch (err: any) {
      logger.warn(`[MongoService] getAgentLogs failed: ${err.message}`);
      throw err;
    }
  }

  // ============================================================================
  // 6. MODEL METADATA OPERATIONS
  // ============================================================================

  /**
   * Upsert model metadata in MongoDB.
   */
  public async createOrUpdateModelMetadata(rawInput: any): Promise<MongoModelMetadata> {
    const validated = validateModelMetadataInput(rawInput);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      localStore.upsertModel({
        id: validated.modelId,
        name: validated.modelName,
        version: validated.version,
        framework: 'Scikit-Learn',
        accuracy: validated.metrics.accuracy || 0.95,
        f1Score: validated.metrics.f1Score || 0.94,
        features: validated.featureNames,
        hyperparameters: validated.hyperparameters,
        status: validated.status
      });
      return { ...validated, _id: validated.modelId };
    }

    try {
      const col = db.collection<MongoModelMetadata>('model_metadata');
      await col.updateOne(
        { modelId: validated.modelId },
        {
          $set: {
            ...validated,
            updatedAt: new Date()
          }
        },
        { upsert: true }
      );

      const saved = await col.findOne({ modelId: validated.modelId });
      return saved || { ...validated, _id: validated.modelId };
    } catch (err: any) {
      logger.warn(`[MongoService] createOrUpdateModelMetadata failed: ${err.message}`);
      return { ...validated, _id: validated.modelId };
    }
  }

  /**
   * Retrieve a specific model by modelId.
   */
  public async getModelMetadata(modelId: string): Promise<MongoModelMetadata | null> {
    const db = await mongoConnection.getDatabase();
    if (!db) {
      const m = localStore.listModels().find((x) => x.id === modelId);
      if (!m) return null;
      return {
        modelId: m.id,
        modelName: m.name,
        algorithm: 'RandomForestClassifier',
        version: m.version,
        status: (m.status as any) || 'ACTIVE',
        datasetUsed: 'CICIDS2017',
        metrics: { accuracy: m.accuracy, f1Score: m.f1Score },
        hyperparameters: m.hyperparameters,
        featureNames: m.features || [],
        trainedAt: new Date(m.createdAt || Date.now()),
        createdAt: new Date(m.createdAt || Date.now()),
        updatedAt: new Date(m.createdAt || Date.now())
      };
    }

    try {
      const col = db.collection<MongoModelMetadata>('model_metadata');
      return await col.findOne({ modelId });
    } catch (err: any) {
      logger.warn(`[MongoService] getModelMetadata failed: ${err.message}`);
      return null;
    }
  }

  /**
   * List all registered models with filtering and pagination.
   */
  public async listModelMetadata(
    filters: { status?: string; algorithm?: string } = {},
    pagination?: MongoPaginationOptions
  ): Promise<MongoPaginatedResult<MongoModelMetadata>> {
    const { limit, offset, page, sortOrder } = this.normalizePagination(pagination);

    const db = await mongoConnection.getDatabase();
    if (!db) {
      const localModels = localStore.listModels();
      const total = localModels.length;
      const sliced = localModels.slice(offset, offset + limit).map((m: any) => ({
        modelId: m.id,
        modelName: m.name,
        algorithm: 'RandomForestClassifier',
        version: m.version,
        status: (m.status as any) || 'ACTIVE',
        datasetUsed: 'CICIDS2017',
        metrics: { accuracy: m.accuracy, f1Score: m.f1Score },
        hyperparameters: m.hyperparameters,
        featureNames: m.features || [],
        trainedAt: new Date(m.createdAt || Date.now()),
        createdAt: new Date(m.createdAt || Date.now()),
        updatedAt: new Date(m.createdAt || Date.now())
      }));

      return {
        data: sliced,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    }

    try {
      const col = db.collection<MongoModelMetadata>('model_metadata');
      const query: Record<string, any> = {};
      if (filters.status) query.status = filters.status.toUpperCase();
      if (filters.algorithm) query.algorithm = { $regex: filters.algorithm, $options: 'i' };

      const [data, total] = await Promise.all([
        col.find(query).sort({ trainedAt: sortOrder }).skip(offset).limit(limit).toArray(),
        col.countDocuments(query)
      ]);

      return {
        data,
        total,
        limit,
        offset,
        page,
        totalPages: Math.ceil(total / limit) || 1,
        hasMore: offset + limit < total
      };
    } catch (err: any) {
      logger.warn(`[MongoService] listModelMetadata failed: ${err.message}`);
      throw err;
    }
  }

  // ============================================================================
  // 7. DASHBOARD STATISTICS AGGREGATION
  // ============================================================================

  /**
   * Compute comprehensive dashboard statistics across collections.
   */
  public async getDashboardStatistics(): Promise<MongoDashboardStats> {
    const db = await mongoConnection.getDatabase();
    if (!db) {
      const localStats = localStore.getStats();
      const events = localStore.listEvents(500);
      const incidents = localStore.listIncidents(100);
      const alerts = localStore.listAlerts(100);
      const detections = localStore.listDetections(100);

      let critical = 0;
      let high = 0;
      let medium = 0;
      let low = 0;

      for (const e of events) {
        const s = (e.severity || 'LOW').toUpperCase();
        if (s === 'CRITICAL') critical++;
        else if (s === 'HIGH') high++;
        else if (s === 'MEDIUM') medium++;
        else low++;
      }

      const activeInc = incidents.filter((i) => i.status !== 'RESOLVED' && i.status !== 'FALSE_POSITIVE').length;
      const resInc = incidents.filter((i) => i.status === 'RESOLVED').length;
      const openAlt = alerts.filter((a) => a.status !== 'RESOLVED' && a.status !== 'FALSE_POSITIVE').length;

      return {
        status: 'ONLINE',
        totalEvents: localStats.totalEvents || events.length,
        threatsDetected: detections.length,
        criticalThreats: critical,
        highThreats: high,
        mediumThreats: medium,
        lowThreats: low,
        activeIncidents: activeInc,
        resolvedIncidents: resInc,
        totalAlerts: alerts.length,
        openAlerts: openAlt,
        agentLogsCount: localStore.listAuditLogs(100).length,
        activeModelsCount: localStore.listModels().length,
        timestamp: new Date().toISOString(),
        source: 'JSON_STORE_FALLBACK'
      };
    }

    try {
      const eventsCol = db.collection<MongoSecurityEvent>('security_events');
      const incidentsCol = db.collection<MongoIncident>('incidents');
      const alertsCol = db.collection<MongoAlert>('alerts');
      const detectionsCol = db.collection<MongoThreatDetection>('threat_detections');
      const logsCol = db.collection<MongoAgentLog>('agent_logs');
      const modelsCol = db.collection<MongoModelMetadata>('model_metadata');

      const [
        totalEvents,
        threatsDetected,
        severityBreakdown,
        activeIncidents,
        resolvedIncidents,
        totalAlerts,
        openAlerts,
        agentLogsCount,
        activeModelsCount
      ] = await Promise.all([
        eventsCol.countDocuments(),
        detectionsCol.countDocuments(),
        eventsCol
          .aggregate<{ _id: string; count: number }>([
            { $group: { _id: '$severity', count: { $sum: 1 } } }
          ])
          .toArray(),
        incidentsCol.countDocuments({ status: { $in: ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED'] } }),
        incidentsCol.countDocuments({ status: 'RESOLVED' }),
        alertsCol.countDocuments(),
        alertsCol.countDocuments({ status: { $in: ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED'] } }),
        logsCol.countDocuments(),
        modelsCol.countDocuments({ status: 'ACTIVE' })
      ]);

      const severityMap: Record<string, number> = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
      };

      for (const item of severityBreakdown) {
        if (item._id && severityMap[item._id.toUpperCase()] !== undefined) {
          severityMap[item._id.toUpperCase()] = item.count;
        }
      }

      return {
        status: 'ONLINE',
        totalEvents,
        threatsDetected,
        criticalThreats: severityMap.CRITICAL,
        highThreats: severityMap.HIGH,
        mediumThreats: severityMap.MEDIUM,
        lowThreats: severityMap.LOW,
        activeIncidents,
        resolvedIncidents,
        totalAlerts,
        openAlerts,
        agentLogsCount,
        activeModelsCount,
        timestamp: new Date().toISOString(),
        source: 'MONGODB'
      };
    } catch (err: any) {
      logger.warn(`[MongoService] getDashboardStatistics aggregation failed: ${err.message}`);
      return {
        status: 'ERROR',
        totalEvents: 0,
        threatsDetected: 0,
        criticalThreats: 0,
        highThreats: 0,
        mediumThreats: 0,
        lowThreats: 0,
        activeIncidents: 0,
        resolvedIncidents: 0,
        totalAlerts: 0,
        openAlerts: 0,
        agentLogsCount: 0,
        activeModelsCount: 0,
        timestamp: new Date().toISOString(),
        source: 'JSON_STORE_FALLBACK'
      };
    }
  }

  // ============================================================================
  // UPGRADE 6: PRODUCTION-READY DATABASE PERSISTENCE OPERATIONS
  // ============================================================================

  /**
   * 1. Persist Raw Event with unique event_id and timestamps
   */
  public async persistRawEvent(rawEvent: MongoRawEvent): Promise<PersistenceWriteResult<MongoRawEvent>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: MongoRawEvent = {
      ...rawEvent,
      stored_at: rawEvent.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoRawEvent>('raw_events');
      const result = await this.executeWithRetry('persistRawEvent', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write was unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoRawEvent>('raw_events');
        const existing = await col.findOne({ event_id: doc.event_id });
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * 2. Persist Normalized Event with unique event_id and timestamps
   */
  public async persistNormalizedEvent(event: MongoNormalizedEvent): Promise<PersistenceWriteResult<MongoNormalizedEvent>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: MongoNormalizedEvent = {
      ...event,
      stored_at: event.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoNormalizedEvent>('normalized_events');
      const result = await this.executeWithRetry('persistNormalizedEvent', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoNormalizedEvent>('normalized_events');
        const existing = await col.findOne({ event_id: doc.event_id });
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * 3. Persist Validation Result with unique event_id
   */
  public async persistValidationResult(validation: MongoValidationResult): Promise<PersistenceWriteResult<MongoValidationResult>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: MongoValidationResult = {
      ...validation,
      stored_at: validation.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoValidationResult>('validation_results');
      const result = await this.executeWithRetry('persistValidationResult', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoValidationResult>('validation_results');
        const existing = await col.findOne({ event_id: doc.event_id });
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * 4. Persist Agent Processing Result with unique event_id + agent_name
   */
  public async persistAgentProcessingResult(agentResult: MongoAgentProcessingResult): Promise<PersistenceWriteResult<MongoAgentProcessingResult>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: MongoAgentProcessingResult = {
      ...agentResult,
      stored_at: agentResult.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoAgentProcessingResult>('agent_processing_results');
      const result = await this.executeWithRetry('persistAgentProcessingResult', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoAgentProcessingResult>('agent_processing_results');
        const existing = await col.findOne({ event_id: doc.event_id, agent_name: doc.agent_name });
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * 5. Persist Correlation with unique correlation_id
   */
  public async persistCorrelation(correlation: MongoCorrelationRecord): Promise<PersistenceWriteResult<MongoCorrelationRecord>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: MongoCorrelationRecord = {
      ...correlation,
      stored_at: correlation.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoCorrelationRecord>('correlations');
      const result = await this.executeWithRetry('persistCorrelation', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoCorrelationRecord>('correlations');
        const existing = await col.findOne({ correlation_id: doc.correlation_id });
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * 6. Persist Threat Detection with unique detection_id
   */
  public async persistThreatDetectionRecord(detection: MongoThreatDetectionRecord): Promise<PersistenceWriteResult<MongoThreatDetectionRecord>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: MongoThreatDetectionRecord = {
      ...detection,
      stored_at: detection.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoThreatDetectionRecord>('threat_detections');
      const result = await this.executeWithRetry('persistThreatDetectionRecord', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoThreatDetectionRecord>('threat_detections');
        const existing = await col.findOne({ detection_id: doc.detection_id });
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * 7. Persist Risk Score with unique event_id
   */
  public async persistRiskScore(risk: MongoRiskScoreRecord): Promise<PersistenceWriteResult<MongoRiskScoreRecord>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: MongoRiskScoreRecord = {
      ...risk,
      stored_at: risk.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoRiskScoreRecord>('risk_scores');
      const result = await this.executeWithRetry('persistRiskScore', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoRiskScoreRecord>('risk_scores');
        const existing = await col.findOne({ event_id: doc.event_id });
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * 8. Persist Alert Record with all 10 required fields and unique alert_id
   */
  public async persistAlertRecord(alert: MongoAlertRecord): Promise<PersistenceWriteResult<MongoAlertRecord>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      localStore.insertAlert({
        id: alert.alert_id,
        alertId: alert.alert_id,
        incidentId: alert.incident_id,
        title: alert.title,
        severity: alert.severity,
        riskScore: alert.risk_score,
        category: alert.category,
        evidence: alert.evidence,
        recommendedAction: alert.recommended_action
      });
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: any = {
      ...alert,
      alertId: alert.alert_id,
      id: alert.alert_id,
      incidentId: alert.incident_id,
      riskScore: alert.risk_score,
      createdAt: new Date(storedAt),
      stored_at: alert.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoAlertRecord>('alerts');
      const result = await this.executeWithRetry('persistAlertRecord', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoAlertRecord>('alerts');
        const existing = await col.findOne({ $or: [{ alert_id: doc.alert_id }, { alertId: doc.alert_id }] } as any);
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * 9. Persist Incident Record with unique incident_id
   */
  public async persistIncidentRecord(incident: MongoIncidentRecord): Promise<PersistenceWriteResult<MongoIncidentRecord>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      localStore.insertIncident({
        incidentId: incident.incident_id,
        id: incident.incident_id,
        title: incident.title,
        description: incident.description,
        severity: (incident.severity || 'HIGH').toUpperCase(),
        status: (incident.status || 'NEW').toUpperCase(),
        riskScore: incident.risk_score,
        assignedTo: incident.assigned_to,
        primaryIp: incident.affected_entities?.[0],
        affectedHost: incident.affected_entities?.[0],
        mitreTechniques: incident.mitre_technique ? [incident.mitre_technique] : []
      });
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: any = {
      ...incident,
      incidentId: incident.incident_id,
      id: incident.incident_id,
      riskScore: incident.risk_score,
      severity: (incident.severity || 'HIGH').toUpperCase(),
      status: (incident.status || 'NEW').toUpperCase(),
      primaryIp: incident.affected_entities?.[0],
      affectedHost: incident.affected_entities?.[0],
      mitreTechniques: incident.mitre_technique ? [incident.mitre_technique] : [],
      createdAt: new Date(storedAt),
      updatedAt: new Date(storedAt),
      stored_at: incident.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoIncidentRecord>('incidents');
      const result = await this.executeWithRetry('persistIncidentRecord', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoIncidentRecord>('incidents');
        const existing = await col.findOne({ $or: [{ incident_id: doc.incident_id }, { incidentId: doc.incident_id }] } as any);
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * 10. Persist Audit Log with unique id
   */
  public async persistAuditLog(audit: MongoAuditLogRecord): Promise<PersistenceWriteResult<MongoAuditLogRecord>> {
    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      return { success: false, status: 'DATABASE_UNAVAILABLE', isDuplicate: false, error: this.lastPersistenceError };
    }

    const storedAt = new Date().toISOString();
    const doc: MongoAuditLogRecord = {
      ...audit,
      stored_at: audit.stored_at || storedAt
    };

    try {
      const col = db.collection<MongoAuditLogRecord>('audit_logs');
      const result = await this.executeWithRetry('persistAuditLog', () => col.insertOne(doc));
      if (!result.acknowledged) {
        this.persistenceFailures++;
        this.lastPersistenceError = 'Write unacknowledged by MongoDB engine';
        return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
      }
      this.lastSuccessfulWrite = storedAt;
      return { success: true, status: 'PERSISTED', isDuplicate: false, doc: { ...doc, _id: result.insertedId }, stored_at: storedAt };
    } catch (err: any) {
      if (err.code === 11000 || err.message?.includes('duplicate key')) {
        const col = db.collection<MongoAuditLogRecord>('audit_logs');
        const existing = await col.findOne({ id: doc.id });
        return { success: true, status: 'DUPLICATE_SKIPPED', isDuplicate: true, doc: existing || doc, stored_at: doc.stored_at };
      }
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: this.lastPersistenceError };
    }
  }

  /**
   * Complete Pipeline Ingestion Persistence:
   * Persists raw event, normalized event, validation, agent results, correlations,
   * threat detections, risk scores, alerts, and incidents across MongoDB collections.
   * Enforces timestamps: received_at, processed_at, stored_at.
   */
  public async persistFullTelemetryPipelineData(input: {
    rawEvent: MongoRawEvent;
    normalizedEvent: MongoNormalizedEvent;
    validationResult: MongoValidationResult;
    agentProcessingResults?: MongoAgentProcessingResult[];
    correlation?: MongoCorrelationRecord;
    threatDetection?: MongoThreatDetectionRecord;
    riskScore?: MongoRiskScoreRecord;
    alert?: MongoAlertRecord;
    incident?: MongoIncidentRecord;
  }): Promise<FullTelemetryPersistenceSummary> {
    const eventId = input.rawEvent.event_id;
    const storedAt = new Date().toISOString();

    const db = await mongoConnection.getVerifiedDatabase();
    if (!db) {
      this.persistenceFailures++;
      this.lastPersistenceError = 'MongoDB connection unverified or server unreachable';
      return {
        eventId,
        success: false,
        status: 'DATABASE_UNAVAILABLE',
        collectionsWritten: [],
        isDuplicate: false,
        error: this.lastPersistenceError,
        storedAt
      };
    }

    const collectionsWritten: string[] = [];
    let isDuplicate = false;

    try {
      // 1. Raw Event
      const rawRes = await this.persistRawEvent(input.rawEvent);
      if (rawRes.success) collectionsWritten.push('raw_events');
      if (rawRes.isDuplicate) isDuplicate = true;

      // 2. Normalized Event
      const normRes = await this.persistNormalizedEvent(input.normalizedEvent);
      if (normRes.success) collectionsWritten.push('normalized_events');

      // 3. Validation Result
      const valRes = await this.persistValidationResult(input.validationResult);
      if (valRes.success) collectionsWritten.push('validation_results');

      // 4. Agent Processing Results
      if (input.agentProcessingResults && input.agentProcessingResults.length > 0) {
        for (const agentRes of input.agentProcessingResults) {
          const res = await this.persistAgentProcessingResult(agentRes);
          if (res.success && !collectionsWritten.includes('agent_processing_results')) {
            collectionsWritten.push('agent_processing_results');
          }
        }
      }

      // 5. Correlation
      if (input.correlation) {
        const corrRes = await this.persistCorrelation(input.correlation);
        if (corrRes.success) collectionsWritten.push('correlations');
      }

      // 6. Threat Detection
      if (input.threatDetection) {
        const detRes = await this.persistThreatDetectionRecord(input.threatDetection);
        if (detRes.success) collectionsWritten.push('threat_detections');
      }

      // 7. Risk Score
      if (input.riskScore) {
        const riskRes = await this.persistRiskScore(input.riskScore);
        if (riskRes.success) collectionsWritten.push('risk_scores');
      }

      // 8. Alert
      if (input.alert) {
        const alertRes = await this.persistAlertRecord(input.alert);
        if (alertRes.success) collectionsWritten.push('alerts');
      }

      // 9. Incident
      if (input.incident) {
        const incRes = await this.persistIncidentRecord(input.incident);
        if (incRes.success) collectionsWritten.push('incidents');
      }

      this.lastSuccessfulWrite = storedAt;

      return {
        eventId,
        success: true,
        status: 'PERSISTED',
        collectionsWritten,
        isDuplicate,
        storedAt
      };
    } catch (err: any) {
      this.persistenceFailures++;
      this.lastPersistenceError = err.message || String(err);
      return {
        eventId,
        success: false,
        status: 'WRITE_FAILED',
        collectionsWritten,
        isDuplicate,
        error: this.lastPersistenceError,
        storedAt
      };
    }
  }
}

export const mongoService = new MongoService();
