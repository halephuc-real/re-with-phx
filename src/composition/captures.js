import { PacketCaptureService } from "../application/captures/PacketCaptureService.js";
import { TsharkCaptureProvider } from "../captures/TsharkCaptureProvider.js";
export const createPacketCaptureService = (environment = process.env) => new PacketCaptureService(new TsharkCaptureProvider(environment));
