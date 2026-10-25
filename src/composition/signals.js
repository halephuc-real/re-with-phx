import { SignalRecordingService } from "../application/signals/SignalRecordingService.js";
import { SigrokRecordingProvider } from "../signals/SigrokRecordingProvider.js";
export const createSignalRecordingService = (environment = process.env) => new SignalRecordingService(new SigrokRecordingProvider(environment));
