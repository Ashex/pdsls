export {
  discoverEnrollment,
  verifyEnrollmentAttestation,
  verifyRecordCid,
  type AttestationResult,
  type StratosEnrollment,
} from "@northskysocial/stratos-client";

export { createServiceClient } from "./client";
export {
  serviceMismatch,
  setStratosActive,
  setStratosEnrollment,
  setTargetEnrollment,
  stratosActive,
  stratosEnrollment,
  stratosMode,
  targetEnrollment,
} from "./state";
