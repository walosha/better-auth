
import { generateRandomString } from "../../crypto/random";
import * as z from "zod";
import { createAuthEndpoint, createAuthMiddleware } from "../../api/call";
import { sessionMiddleware } from "../../api";
import { symmetricDecrypt } from "../../crypto";
import type { BetterAuthPlugin } from "../../types/plugins";
import { mergeSchema } from "../../db/schema";
import { APIError } from "better-call";
import { deleteSessionCookie } from "../../cookies";
import { createHash } from "@better-auth/utils/hash";
import { base64Url } from "@better-auth/utils/base64";
import type { GenericEndpointContext, User } from "../../types";
import type { DeviceBindingOptions, DeviceInfo, TrustedDevice } from "./types";
import { schema, type DeviceBinding, type DeviceVerificationOTP } from "./schema";

export interface UserWithDeviceBinding extends User {
  hasRegisteredDevice: boolean;
  phoneNumberVerified: boolean;
  deviceId: string;
}

// Enhanced device fingerprinting with canvas and WebGL
async function defaultDeviceFingerprinting(context: GenericEndpointContext): Promise<string> {
  const headers = context.headers;
  const userAgent = headers?.get("user-agent") || "";
  const acceptLanguage = headers?.get("accept-language") || "";
  const acceptEncoding = headers?.get("accept-encoding") || "";
  const xForwardedFor = headers?.get("x-forwarded-for") || "";
  const xRealIp = headers?.get("x-real-ip") || "";
  
  const deviceInfo = (context.body)?.deviceInfo as DeviceInfo || {};
  
  const fingerprintData = {
    userAgent,
    acceptLanguage,
    acceptEncoding,
    ipPrefix: (xForwardedFor || xRealIp).split('.').slice(0, 2).join('.'),
    screenResolution: deviceInfo.screenResolution,
    timezone: deviceInfo.timezone,
    language: deviceInfo.language,
    platform: deviceInfo.platform,
    cookiesEnabled: deviceInfo.cookiesEnabled,
    doNotTrack: deviceInfo.doNotTrack,
    hardwareConcurrency: deviceInfo.hardwareConcurrency,
    maxTouchPoints: deviceInfo.maxTouchPoints,
    colorDepth: deviceInfo.colorDepth,
    pixelRatio: deviceInfo.pixelRatio,
    canvas: deviceInfo.canvas,
    webgl: deviceInfo.webgl,
  };
  
  const fingerprintString = JSON.stringify(fingerprintData);
  const hash = await createHash("SHA-256").digest(
    new TextEncoder().encode(fingerprintString)
  );
  
  return base64Url.encode(new Uint8Array(hash), { padding: false });
}

const DEVICE_BINDING_COOKIE_NAME = "better_auth_device_binding";

// Generate OTP for device verification
function generateOTP(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Default OTP sender (should be overridden in production)
async function defaultSendOTP(userId: string, deviceInfo: DeviceInfo): Promise<string> {
  const otp = generateOTP();
  console.log(`Device verification OTP for user ${userId}: ${otp}`);
  return otp;
}

// Enhanced 2FA verification
async function verify2FA(
  ctx: any,
  userId: string, 
  totpCode?: string, 
  otpCode?: string,
  options?: DeviceBindingOptions
): Promise<boolean> {
  if (totpCode && options?.verifyTOTP) {
    return await options.verifyTOTP(userId, totpCode);
  }
  
  if (otpCode && options?.verifyOTP) {
    return await options.verifyOTP(userId, otpCode);
  }
  
  // Fallback: Check against two-factor plugin
  if (totpCode) {
    try {
      const twoFactor = await ctx.context.adapter.findOne({
        model: "twoFactor",
        where: [{ field: "userId", value: userId }],
      });
      
      if (!twoFactor) {
        throw new APIError("BAD_REQUEST", { message: "2FA not enabled" });
      }
      
      const decryptedSecret = await symmetricDecrypt({
        key: ctx.context.secret,
        data: twoFactor.secret,
      });
      
      const { createOTP } = await import("@better-auth/utils/otp");
      const otp = createOTP(decryptedSecret);
      return otp.verify(totpCode);
    } catch (error) {
      console.error("2FA verification failed:", error);
      return false;
    }
  }
  
  return false;
}

export const deviceBinding = (options?: DeviceBindingOptions) => {
  const opts = {
    trustDuration: options?.trustDuration || 30,
    maxTrustedDevices: options?.maxTrustedDevices || 3,
    requireDeviceVerification: options?.requireDeviceVerification ?? true,
    generateDeviceFingerprint: options?.generateDeviceFingerprint || defaultDeviceFingerprinting,
    autoRegisterDevice: options?.autoRegisterDevice ?? false,
    strictMode: options?.strictMode ?? true,
    deviceBindingTable: options?.deviceBindingTable || "deviceBinding",
    otpTable: options?.otpTable || "deviceVerificationOTP",
    sendOTP: options?.sendOTP || defaultSendOTP,
  };

  return {
    id: "device-binding",
    endpoints: {
      /**
       * Register a new device (only for first-time users in strict mode)
       */
      registerDevice: createAuthEndpoint(
        "/device-binding/register",
        {
          method: "POST",
          body: z.object({
            deviceInfo: z.object({
              userAgent: z.string().optional(),
              screenResolution: z.string().optional(),
              timezone: z.string().optional(),
              language: z.string().optional(),
              platform: z.string().optional(),
              cookiesEnabled: z.boolean().optional(),
              doNotTrack: z.boolean().optional(),
              hardwareConcurrency: z.number().optional(),
              maxTouchPoints: z.number().optional(),
              colorDepth: z.number().optional(),
              pixelRatio: z.number().optional(),
              canvas: z.string().optional(),
              webgl: z.string().optional(),
            }).optional(),
            deviceName: z.string().optional(),
            isFirstDevice: z.boolean().optional(),
          }),
          use: [sessionMiddleware],
          metadata: {
            openapi: {
              summary: "Register a new device",
              description: "Register the current device for device binding",
            },
          },
        },
        async (ctx) => {
          const user = ctx.context.session.user;
          const { deviceInfo, deviceName, isFirstDevice } = ctx.body;
          
          // Generate device fingerprint
          const deviceFingerprint = await opts.generateDeviceFingerprint(ctx);
          const deviceId = generateRandomString(32);
          
          // Check if user has any registered devices
          const existingDevicesCount = await ctx.context.adapter.count({
            model: opts.deviceBindingTable,
            where: [{ field: "userId", value: user.id }],
          });
          
          // In strict mode, only allow registration if it's the first device
          if (opts.strictMode && existingDevicesCount > 0 && !isFirstDevice) {
            throw new APIError("FORBIDDEN", {
              message: "New device registration not allowed. Please use device verification instead.",
            });
          }
          
          // Check if device already exists
          const existingDevice = await ctx.context.adapter.findOne<DeviceBinding>({
            model: opts.deviceBindingTable,
            where: [
              { field: "userId", value: user.id },
              { field: "deviceFingerprint", value: deviceFingerprint },
            ],
          });
          
          if (existingDevice) {
            await ctx.context.adapter.update<DeviceBinding>({
              model: opts.deviceBindingTable,
              where: [{ field: "id", value: existingDevice.id }],
              update: {
                lastSeenAt: new Date(),
                deviceName: deviceName || existingDevice.deviceName,
              },
            });
            
            return ctx.json({
              deviceId: existingDevice.deviceId,
              trusted: existingDevice.trusted,
              isNewDevice: false,
            });
          }
          
          // Create new device (auto-trusted if first device)
          const isFirstUserDevice = existingDevicesCount === 0;
          const newDevice = await ctx.context.adapter.create({
            model: opts.deviceBindingTable,
            data: {
              id: generateRandomString(32),
              userId: user.id,
              deviceId,
              deviceFingerprint,
              deviceName: deviceName || generateDeviceName(deviceInfo),
              trusted: isFirstUserDevice,
              trustedAt: isFirstUserDevice ? new Date() : null,
              lastSeenAt: new Date(),
              createdAt: new Date(),
              expiresAt: isFirstUserDevice 
                ? new Date(Date.now() + opts.trustDuration * 24 * 60 * 60 * 1000)
                : null,
              isFirstDevice: isFirstUserDevice,
            },
          });
          
          if (isFirstUserDevice) {
            // Update user to mark as having registered device
            await ctx.context.adapter.update({
              model: "user",
              where: [{ field: "id", value: user.id }],
              update: { hasRegisteredDevice: true },
            });
            
            await setDeviceBindingCookie(ctx, deviceId, deviceFingerprint);
          }
          
          return ctx.json({
            deviceId: newDevice.deviceId,
            trusted: newDevice.trusted,
            isNewDevice: true,
            requiresVerification: !isFirstUserDevice,
          });
        }
      ),

      /**
       * Request OTP for device verification
       */
      requestDeviceOTP: createAuthEndpoint(
        "/device-binding/request-otp",
        {
          method: "POST",
          body: z.object({
            deviceInfo: z.object({
              userAgent: z.string().optional(),
              screenResolution: z.string().optional(),
              timezone: z.string().optional(),
              language: z.string().optional(),
              platform: z.string().optional(),
              cookiesEnabled: z.boolean().optional(),
              doNotTrack: z.boolean().optional(),
              hardwareConcurrency: z.number().optional(),
              maxTouchPoints: z.number().optional(),
              colorDepth: z.number().optional(),
              pixelRatio: z.number().optional(),
              canvas: z.string().optional(),
              webgl: z.string().optional(),
            }).optional(),
            email: z.string().email(),
          }),
          metadata: {
            openapi: {
              summary: "Request OTP for device verification",
              description: "Request an OTP to verify a new device",
            },
          },
        },
        async (ctx) => {
          const { deviceInfo, email } = ctx.body;
          
          // Find user by email
          const user = await ctx.context.adapter.findOne<UserWithDeviceBinding>({
            model: "user",
            where: [{ field: "email", value: email }],
          });
          
          if (!user) {
            throw new APIError("NOT_FOUND", { message: "User not found" });
          }
          
          // Check if user has registered devices (prevent first-time bypass)
          if (!user.hasRegisteredDevice) {
            throw new APIError("BAD_REQUEST", {
              message: "Please complete initial device registration first",
            });
          }
          
          const deviceFingerprint = await opts.generateDeviceFingerprint(ctx);
          const deviceId = generateRandomString(32);
          
          // Clean up expired OTPs
          await ctx.context.adapter.delete({
            model: opts.otpTable,
            where: [
              { field: "userId", value: user.id },
              { field: "expiresAt", value: new Date(), operator: "lt" },
            ],
          });
          
          // Generate OTP
          const otp = await opts.sendOTP(user.id, deviceInfo || {});
          
          // Store OTP
          await ctx.context.adapter.create({
            model: opts.otpTable,
            data: {
              id: generateRandomString(32),
              userId: user.id,
              deviceId,
              otp: await createHash("SHA-256").digest(new TextEncoder().encode(otp)),
              verified: false,
              attempts: 0,
              createdAt: new Date(),
              expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
            },
          });
          
          return ctx.json({
            success: true,
            deviceId,
            message: "OTP sent successfully",
            expiresIn: 600, // 10 minutes in seconds
          });
        }
      ),

      /**
       * Verify device with OTP
       */
      verifyDeviceOTP: createAuthEndpoint(
        "/device-binding/verify-otp",
        {
          method: "POST",
          body: z.object({
            deviceId: z.string(),
            otp: z.string(),
            deviceInfo: z.object({
              userAgent: z.string().optional(),
              screenResolution: z.string().optional(),
              timezone: z.string().optional(),
              language: z.string().optional(),
              platform: z.string().optional(),
              cookiesEnabled: z.boolean().optional(),
              doNotTrack: z.boolean().optional(),
              hardwareConcurrency: z.number().optional(),
              maxTouchPoints: z.number().optional(),
              colorDepth: z.number().optional(),
              pixelRatio: z.number().optional(),
              canvas: z.string().optional(),
              webgl: z.string().optional(),
            }).optional(),
            trustDevice: z.boolean().optional(),
          }),
          metadata: {
            openapi: {
              summary: "Verify device with OTP",
              description: "Verify a device using the OTP sent to the user",
            },
          },
        },
        async (ctx) => {
          const { deviceId, otp, deviceInfo, trustDevice } = ctx.body;
          
          // Find OTP record
          const otpRecord = await ctx.context.adapter.findOne<DeviceVerificationOTP>({
            model: opts.otpTable,
            where: [
              { field: "deviceId", value: deviceId },
              { field: "verified", value: false },
              { field: "expiresAt", value: new Date(), operator: "gt" },
            ],
          });
          
          if (!otpRecord) {
            throw new APIError("BAD_REQUEST", {
              message: "Invalid or expired OTP",
            });
          }
          
          // Check attempts limit
          if (otpRecord.attempts >= 5) {
            throw new APIError("BAD_REQUEST", {
              message: "Too many failed attempts. Please request a new OTP.",
            });
          }
          
          // Verify OTP
          const hashedOTP = await createHash("SHA-256").digest(new TextEncoder().encode(otp));
          const isValidOTP = base64Url.encode(new Uint8Array(hashedOTP)) === otpRecord.otp;
          
          if (!isValidOTP) {
            // Increment attempts
            await ctx.context.adapter.update({
              model: opts.otpTable,
              where: [{ field: "id", value: otpRecord.id }],
              update: { attempts: otpRecord.attempts + 1 },
            });
            
            throw new APIError("BAD_REQUEST", {
              message: "Invalid OTP",
            });
          }
          
          // Mark OTP as verified
          await ctx.context.adapter.update({
            model: opts.otpTable,
            where: [{ field: "id", value: otpRecord.id }],
            update: { verified: true },
          });
          
          // Generate device fingerprint
          const deviceFingerprint = await opts.generateDeviceFingerprint(ctx);
          
          // Check trusted device limit if trying to trust
          if (trustDevice) {
            const trustedDevicesCount = await ctx.context.adapter.count({
              model: opts.deviceBindingTable,
              where: [
                { field: "userId", value: otpRecord.userId },
                { field: "trusted", value: true },
              ],
            });
            
            if (trustedDevicesCount >= opts.maxTrustedDevices) {
              throw new APIError("BAD_REQUEST", {
                message: `Maximum trusted devices limit (${opts.maxTrustedDevices}) reached`,
              });
            }
          }
          
          // Create or update device binding
          const existingDevice = await ctx.context.adapter.findOne<DeviceBinding>({
            model: opts.deviceBindingTable,
            where: [
              { field: "userId", value: otpRecord.userId },
              { field: "deviceFingerprint", value: deviceFingerprint },
            ],
          });
          
          let deviceBinding: DeviceBinding | null;
          if (existingDevice) {
            deviceBinding = await ctx.context.adapter.update<DeviceBinding>({
              model: opts.deviceBindingTable,
              where: [{ field: "id", value: existingDevice.id }],
              update: {
                trusted: trustDevice || existingDevice.trusted,
                trustedAt: trustDevice && !existingDevice.trusted ? new Date() : existingDevice.trustedAt,
                lastSeenAt: new Date(),
                expiresAt: trustDevice 
                  ? new Date(Date.now() + opts.trustDuration * 24 * 60 * 60 * 1000)
                  : existingDevice.expiresAt,
              },
            });
          } else {
            deviceBinding = await ctx.context.adapter.create({
              model: opts.deviceBindingTable,
              data: {
                id: generateRandomString(32),
                userId: otpRecord.userId,
                deviceId: generateRandomString(32),
                deviceFingerprint,
                deviceName: generateDeviceName(deviceInfo),
                trusted: trustDevice || false,
                trustedAt: trustDevice ? new Date() : null,
                lastSeenAt: new Date(),
                createdAt: new Date(),
                expiresAt: trustDevice 
                  ? new Date(Date.now() + opts.trustDuration * 24 * 60 * 60 * 1000)
                  : null,
                isFirstDevice: false,
              },
            });
          }
          
          if (trustDevice) {
            await setDeviceBindingCookie(ctx, deviceBinding!.deviceId, deviceFingerprint);
          }
          
          return ctx.json({
            success: true,
            deviceId: deviceBinding!.deviceId,
            trusted: deviceBinding!.trusted,
            message: "Device verified successfully",
          });
        }
      ),

      /**
       * Trust a device (requires 2FA verification)
       */
      trustDevice: createAuthEndpoint(
        "/device-binding/trust",
        {
          method: "POST",
          body: z.object({
            deviceId: z.string(),
            totpCode: z.string().optional(),
            otpCode: z.string().optional(),
          }),
          use: [sessionMiddleware],
          metadata: {
            openapi: {
              summary: "Trust a device",
              description: "Trust a device with 2FA verification",
            },
          },
        },
        async (ctx) => {
          const user = ctx.context.session.user;
          const { deviceId, totpCode, otpCode } = ctx.body;
          
          // Verify 2FA code
          const is2FAValid = await verify2FA(ctx, user.id, totpCode, otpCode, options);
          if (!is2FAValid) {
            throw new APIError("BAD_REQUEST", {
              message: "Invalid 2FA code",
            });
          }
          
          const device = await ctx.context.adapter.findOne<DeviceBinding>({
            model: opts.deviceBindingTable,
            where: [
              { field: "userId", value: user.id },
              { field: "deviceId", value: deviceId },
            ],
          });
          
          if (!device) {
            throw new APIError("NOT_FOUND", {
              message: "Device not found",
            });
          }
          
          // Check trusted device limit
          const trustedDevicesCount = await ctx.context.adapter.count({
            model: opts.deviceBindingTable,
            where: [
              { field: "userId", value: user.id },
              { field: "trusted", value: true },
            ],
          });
          
          if (!device.trusted && trustedDevicesCount >= opts.maxTrustedDevices) {
            throw new APIError("BAD_REQUEST", {
              message: `Maximum trusted devices limit (${opts.maxTrustedDevices}) reached`,
            });
          }
          
          // Trust the device
          const updatedDevice = await ctx.context.adapter.update<DeviceBinding>({
            model: opts.deviceBindingTable,
            where: [{ field: "id", value: device.id }],
            update: {
              trusted: true,
              trustedAt: new Date(),
              expiresAt: new Date(Date.now() + opts.trustDuration * 24 * 60 * 60 * 1000),
            },
          });
          
          await setDeviceBindingCookie(ctx, deviceId, device.deviceFingerprint);
          
          return ctx.json({
            success: true,
            deviceId: updatedDevice!.deviceId,
          });
        }
      ),

      /**
       * List user's devices
       */
      listDevices: createAuthEndpoint(
        "/device-binding/list",
        {
          method: "GET",
          use: [sessionMiddleware],
          metadata: {
            openapi: {
              summary: "List user devices",
              description: "Get list of all registered devices for the user",
            },
          },
        },
        async (ctx) => {
          const user = ctx.context.session.user;
          const currentFingerprint = await opts.generateDeviceFingerprint(ctx);
          
          const devices = await ctx.context.adapter.findMany({
            model: opts.deviceBindingTable,
            where: [{ field: "userId", value: user.id }],
          });
          
          return ctx.json({
            devices: devices.map((device: any) => ({
              deviceId: device.deviceId,
              deviceName: device.deviceName,
              trusted: device.trusted,
              trustedAt: device.trustedAt,
              lastSeenAt: device.lastSeenAt,
              createdAt: device.createdAt,
              expiresAt: device.expiresAt,
              isFirstDevice: device.isFirstDevice,
              isCurrent: device.deviceFingerprint === currentFingerprint,
            })),
          });
        }
      ),

      /**
       * Remove/untrust a device
       */
      removeDevice: createAuthEndpoint(
        "/device-binding/remove",
        {
          method: "POST",
          body: z.object({
            deviceId: z.string(),
          }),
          use: [sessionMiddleware],
          metadata: {
            openapi: {
              summary: "Remove a device",
              description: "Remove a device from the user's trusted devices",
            },
          },
        },
        async (ctx) => {
          const user = ctx.context.session.user;
          const { deviceId } = ctx.body;
          
          const device = await ctx.context.adapter.findOne<DeviceBinding>({
            model: opts.deviceBindingTable,
            where: [
              { field: "userId", value: user.id },
              { field: "deviceId", value: deviceId },
            ],
          });
          
          if (!device) {
            throw new APIError("NOT_FOUND", {
              message: "Device not found",
            });
          }
          
          // Prevent removal of first device if it's the only trusted device
          if (device.isFirstDevice) {
            const trustedDevicesCount = await ctx.context.adapter.count({
              model: opts.deviceBindingTable,
              where: [
                { field: "userId", value: user.id },
                { field: "trusted", value: true },
              ],
            });
            
            if (trustedDevicesCount <= 1) {
              throw new APIError("BAD_REQUEST", {
                message: "Cannot remove the only trusted device",
              });
            }
          }
          
          await ctx.context.adapter.delete({
            model: opts.deviceBindingTable,
            where: [{ field: "id", value: device.id }],
          });
          
          return ctx.json({ success: true });
        }
      ),

      /**
       * Check if current device is trusted
       */
      checkDeviceStatus: createAuthEndpoint(
        "/device-binding/status",
        {
          method: "GET",
          use: [sessionMiddleware],
          metadata: {
            openapi: {
              summary: "Check device status",
              description: "Check if the current device is trusted",
            },
          },
        },
        async (ctx) => {
          const user = ctx.context.session.user;
          const currentFingerprint = await opts.generateDeviceFingerprint(ctx);
          
          const device = await ctx.context.adapter.findOne<DeviceBinding>({
            model: opts.deviceBindingTable,
            where: [
              { field: "userId", value: user.id },
              { field: "deviceFingerprint", value: currentFingerprint },
            ],
          });
          
          return ctx.json({
            deviceRegistered: !!device,
            trusted: device?.trusted || false,
            deviceId: device?.deviceId || null,
            expiresAt: device?.expiresAt || null,
            isFirstDevice: device?.isFirstDevice || false,
          });
        }
      ),
    },
    
    hooks: {
      after: [
        {
          matcher(context) {
            return (
              context.path === "/sign-in/email" ||
              context.path === "/sign-in/username" ||
              context.path === "/sign-in/phone-number" ||
              context.path === "/sign-up/email" ||
              context.path === "/sign-up/username" ||
              context.path === "/sign-up/phone-number"
            );
          },
          handler: createAuthMiddleware(async (ctx) => {
            const data = ctx.context.newSession;
            if (!data || !data.user.deviceBindingEnabled) {
              return;
            }
            
            // Generate current device fingerprint
            const currentFingerprint = await opts.generateDeviceFingerprint(ctx);
            
            // Check for device binding cookie
            const deviceBindingCookieName = ctx.context.createAuthCookie(
              DEVICE_BINDING_COOKIE_NAME
            );
            const deviceBindingCookie = await ctx.getSignedCookie(
              deviceBindingCookieName.name,
              ctx.context.secret
            );
            
            let trustedDevice = null;
            
            // Check cookie-based trust first
            if (deviceBindingCookie) {
              const [deviceId, fingerprint] = deviceBindingCookie.split("!");
              
              if (fingerprint === currentFingerprint) {
                trustedDevice = await ctx.context.adapter.findOne<DeviceBinding>({
                  model: opts.deviceBindingTable,
                  where: [
                    { field: "userId", value: data.user.id },
                    { field: "deviceId", value: deviceId },
                    { field: "deviceFingerprint", value: fingerprint },
                    { field: "trusted", value: true },
                  ],
                });
                
                // Check expiration
                if (trustedDevice && trustedDevice.expiresAt && new Date() > new Date(trustedDevice.expiresAt)) {
                  trustedDevice = null;
                  // Clear expired cookie
                  await ctx.setCookie(deviceBindingCookieName.name, "", { maxAge: 0 });
                }
              }
            }
            
            // Fallback: Check fingerprint-based trust
            if (!trustedDevice) {
              trustedDevice = await ctx.context.adapter.findOne<DeviceBinding>({
                model: opts.deviceBindingTable,
                where: [
                  { field: "userId", value: data.user.id },
                  { field: "deviceFingerprint", value: currentFingerprint },
                  { field: "trusted", value: true },
                ],
              });
              
              // Check expiration
              if (trustedDevice && trustedDevice.expiresAt && new Date() > new Date(trustedDevice.expiresAt)) {
                await ctx.context.adapter.update({
                  model: opts.deviceBindingTable,
                  where: [{ field: "id", value: trustedDevice.id }],
                  update: { trusted: false, trustedAt: null, expiresAt: null },
                });
                trustedDevice = null;
              }
            }
            
            // Check if user has any registered devices
            const userDevicesCount = await ctx.context.adapter.count({
              model: opts.deviceBindingTable,
              where: [{ field: "userId", value: data.user.id }],
            });
            
            // Handle first-time users (no devices registered)
            if (userDevicesCount === 0) {
              if (opts.autoRegisterDevice || !opts.strictMode) {
                try {
                  const deviceId = generateRandomString(32);
                  await ctx.context.adapter.create({
                    model: opts.deviceBindingTable,
                    data: {
                      id: generateRandomString(32),
                      userId: data.user.id,
                      deviceId,
                      deviceFingerprint: currentFingerprint,
                      deviceName: generateDeviceName(),
                      trusted: true, // First device is auto-trusted
                      trustedAt: new Date(),
                      lastSeenAt: new Date(),
                      createdAt: new Date(),
                      expiresAt: new Date(Date.now() + opts.trustDuration * 24 * 60 * 60 * 1000),
                      isFirstDevice: true,
                    },
                  });
                  
                  // Mark user as having registered device
                  await ctx.context.adapter.update({
                    model: "user",
                    where: [{ field: "id", value: data.user.id }],
                    update: { hasRegisteredDevice: true },
                  });
                  
                  await setDeviceBindingCookie(ctx, deviceId, currentFingerprint);
                  return; // Allow login
                } catch (error) {
                  console.warn("Failed to auto-register first device:", error);
                }
              }
              
              // If auto-registration fails or is disabled, require manual registration
              deleteSessionCookie(ctx, true);
              await ctx.context.internalAdapter.deleteSession(data.session.token);
              
              return ctx.json({
                deviceVerificationRequired: true,
                isFirstDevice: true,
                message: "Please register your first device",
              });
            }
            
            // Handle existing users with trusted device
            if (trustedDevice) {
              // Update last seen and refresh expiration
              await ctx.context.adapter.update({
                model: opts.deviceBindingTable,
                where: [{ field: "id", value: trustedDevice.id }],
                update: {
                  lastSeenAt: new Date(),
                  expiresAt: new Date(Date.now() + opts.trustDuration * 24 * 60 * 60 * 1000),
                },
              });
              
              await setDeviceBindingCookie(ctx, trustedDevice.deviceId, trustedDevice.deviceFingerprint);
              return; // Allow login
            }
            
            // Handle existing users on untrusted device
            const existingDevice = await ctx.context.adapter.findOne<DeviceBinding>({
              model: opts.deviceBindingTable,
              where: [
                { field: "userId", value: data.user.id },
                { field: "deviceFingerprint", value: currentFingerprint },
              ],
            });
            
            if (existingDevice && !existingDevice.trusted) {
              // Update last seen for existing untrusted device
              await ctx.context.adapter.update({
                model: opts.deviceBindingTable,
                where: [{ field: "id", value: existingDevice.id }],
                update: { lastSeenAt: new Date() },
              });
            } else if (!existingDevice && opts.autoRegisterDevice) {
              // Register new untrusted device
              try {
                const deviceId = generateRandomString(32);
                await ctx.context.adapter.create({
                  model: opts.deviceBindingTable,
                  data: {
                    id: generateRandomString(32),
                    userId: data.user.id,
                    deviceId,
                    deviceFingerprint: currentFingerprint,
                    deviceName: generateDeviceName(),
                    trusted: false,
                    lastSeenAt: new Date(),
                    createdAt: new Date(),
                    isFirstDevice: false,
                  },
                });
              } catch (error) {
                console.warn("Failed to auto-register untrusted device:", error);
              }
            }
            
            // Block login on untrusted device
            if (opts.requireDeviceVerification) {
              deleteSessionCookie(ctx, true);
              await ctx.context.internalAdapter.deleteSession(data.session.token);
              
              return ctx.json({
                deviceVerificationRequired: true,
                isNewDevice: !existingDevice,
                deviceId: existingDevice?.deviceId,
                message: "Device verification required. Please verify this device using OTP.",
              });
            }
          }),
        },
      ],
    },
    
    schema: mergeSchema(schema, options?.schema),
    
    rateLimit: [
      {
        pathMatcher(path) {
          return path.startsWith("/device-binding/");
        },
        window: 10,
        max: 15,
      },
      {
        pathMatcher(path) {
          return path === "/device-binding/request-otp";
        },
        window: 60,
        max: 3, // Strict rate limit for OTP requests
      },
      {
        pathMatcher(path) {
          return path === "/device-binding/verify-otp";
        },
        window: 60,
        max: 10, // Allow multiple verification attempts
      },
    ],
  } satisfies BetterAuthPlugin;
};

// Helper function to set device binding cookie
async function setDeviceBindingCookie(
  ctx: any,
  deviceId: string,
  deviceFingerprint: string
) {
  const deviceBindingCookieName = ctx.context.createAuthCookie(
    DEVICE_BINDING_COOKIE_NAME,
    {
      maxAge: 30 * 24 * 60 * 60, // 30 days
      httpOnly: true,
      secure: true,
      sameSite: "lax",
    }
  );
  
  await ctx.setSignedCookie(
    deviceBindingCookieName.name,
    `${deviceId}!${deviceFingerprint}`,
    ctx.context.secret,
    deviceBindingCookieName.attributes
  );
}

// Helper function to generate device names
function generateDeviceName(deviceInfo?: DeviceInfo): string {
  if (!deviceInfo) {
    return `Device ${new Date().toLocaleDateString()}`;
  }
  
  const { platform, userAgent } = deviceInfo;
  
  if (platform) {
    if (platform.includes("Win")) return "Windows Device";
    if (platform.includes("Mac")) return "Mac Device";
    if (platform.includes("Linux")) return "Linux Device";
    if (platform.includes("iPhone") || platform.includes("iPad")) return "iOS Device";
    if (platform.includes("Android")) return "Android Device";
  }
  
  if (userAgent) {
    if (userAgent.includes("Chrome")) return "Chrome Browser";
    if (userAgent.includes("Firefox")) return "Firefox Browser";
    if (userAgent.includes("Safari") && !userAgent.includes("Chrome")) return "Safari Browser";
    if (userAgent.includes("Edge")) return "Edge Browser";
  }
  
  return `Device ${new Date().toLocaleDateString()}`;
}