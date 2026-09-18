/**
 * Core Data Quality and Schema Validation Types
 * Strictly enforces per-row validation auditing and structured error metrics
 */

export type RowValidationStatus = 'VALID' | 'WARNING' | 'INVALID' | 'DUPLICATE' | 'PROCESSING_ERROR';

export type ValidationErrorSeverity = 'ERROR' | 'WARNING' | 'CRITICAL';

export interface ValidationErrorItem {
  field: string;
  error_code: string;
  message: string;
  severity: ValidationErrorSeverity;
  original_value: unknown;
}

export interface StructuredValidationResult {
  row_id: string | number;
  event_id: string;
  is_valid: boolean;
  validation_status: RowValidationStatus;
  status?: 'VALID' | 'INVALID';
  errors: ValidationErrorItem[];
  warnings: ValidationErrorItem[];
  original_data: Record<string, unknown> | string;
  normalized_data: Record<string, unknown> | null;
  detected_at: string;
}

export interface ValidationSummary {
  total: number;
  valid: number;
  invalid: number;
  warning: number;
  duplicate: number;
  processingErrors: number;
  validationPercentage: number;
  errorCountsByCode: Record<string, number>;
  timestamp?: string;
}

export interface ValidationErrorFilterCriteria {
  status?: 'ALL' | RowValidationStatus;
  errorCode?: string;
  field?: string;
  searchTerm?: string;
  limit?: number;
  offset?: number;
}
