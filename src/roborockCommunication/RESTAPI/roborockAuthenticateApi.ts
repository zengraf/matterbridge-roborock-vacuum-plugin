import axios, { AxiosError, AxiosInstance, AxiosStatic } from 'axios';
import crypto from 'node:crypto';
import { AnsiLogger } from 'matterbridge/logger';
import { URLSearchParams } from 'node:url';
import { AuthenticateResponse } from '../Zmodel/authenticateResponse.js';
import { BaseUrl } from '../Zmodel/baseURL.js';
import { HomeInfo } from '../Zmodel/homeInfo.js';
import { UserData } from '../Zmodel/userData.js';
import { SignCodeV3 } from '../Zmodel/signCodeV3.js';

export interface UrlByEmailResult {
  baseUrl: string;
  country: string;
  countryCode: string;
}

export class RoborockApiError extends Error {
  public readonly code?: number;
  public readonly apiMessage?: string;

  constructor(message: string, code?: number, apiMessage?: string) {
    super(message);
    this.name = 'RoborockApiError';
    this.code = code;
    this.apiMessage = apiMessage;
  }
}

/**
 * Extracts a meaningful error message from various error types
 */
function extractErrorMessage(error: unknown, context: string): RoborockApiError {
  if (error instanceof RoborockApiError) {
    return error;
  }

  if (error instanceof AxiosError) {
    const status = error.response?.status;
    const data = error.response?.data as { msg?: string; code?: number; message?: string } | undefined;
    const apiMsg = data?.msg || data?.message || error.message;
    const apiCode = data?.code || status;
    return new RoborockApiError(`${context}: ${apiMsg} (status: ${status})`, apiCode, apiMsg);
  }

  if (error instanceof Error) {
    return new RoborockApiError(`${context}: ${error.message}`);
  }

  return new RoborockApiError(`${context}: ${String(error)}`);
}

export class RoborockAuthenticateApi {
  private readonly logger: AnsiLogger;
  private axiosFactory: AxiosStatic;
  private deviceId: string;
  private username?: string;
  private authToken?: string;
  private country = '';
  private countryCode = '';

  constructor(logger: AnsiLogger, axiosFactory: AxiosStatic = axios) {
    this.deviceId = crypto.randomUUID();
    this.axiosFactory = axiosFactory;
    this.logger = logger;
  }

  public async loginWithUserData(username: string, userData: UserData): Promise<UserData> {
    this.loginWithAuthToken(username, userData.token);
    return userData;
  }

  /**
   * Requests a 2FA code to be sent to the user's email.
   * @param username The user's email address
   * @returns The base URL and country information for subsequent API calls
   */
  public async requestCode(username: string): Promise<UrlByEmailResult> {
    // Clear any existing auth token to ensure a fresh authentication
    this.authToken = undefined;
    this.username = undefined;

    try {
      const urlResult = await this.getUrlByEmail(username);

      const api = await this.apiForUser(username, urlResult.baseUrl);
      const response = await api.post(
        'api/v4/email/code/send',
        new URLSearchParams({
          email: username,
          type: 'login',
          platform: '',
        }).toString(),
        {
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            header_clientlang: 'en',
          },
        },
      );

      // Check if the API returned an error in the response body
      const data = response.data as { code?: number; msg?: string };
      if (data.code && data.code !== 200 && data.code !== 0) {
        throw new RoborockApiError(`Failed to send 2FA code: ${data.msg}`, data.code, data.msg);
      }

      this.logger.debug('2FA code request sent successfully');
      return urlResult;
    } catch (error) {
      throw extractErrorMessage(error, 'Failed to request 2FA code');
    }
  }

  /**
   * Logs in with a 2FA code using the V1 API.
   * @param username The user's email address
   * @param twofa The 2FA code received via email
   * @param baseUrl The base URL obtained from requestCode
   * @returns UserData containing authentication tokens
   */
  public async loginWithCode(username: string, twofa: string, baseUrl: string): Promise<UserData> {
    try {
      const api = await this.apiForUser(username, baseUrl);
      const response = await api.post(
        'api/v1/login',
        new URLSearchParams({
          username: username,
          verifycode: twofa,
          verifycodetype: 'AUTH_EMAIL_CODE',
        }).toString(),
      );
      return this.auth(username, response.data);
    } catch (error) {
      throw extractErrorMessage(error, 'Login with 2FA code failed');
    }
  }

  /**
   * Logs in with a 2FA code using the V4 API (preferred method when country info is available).
   * @param username The user's email address
   * @param twofa The 2FA code received via email
   * @param baseUrl The base URL obtained from requestCode
   * @param country The country name
   * @param countryCode The country code
   * @returns UserData containing authentication tokens
   */
  public async loginWithCodeV4(username: string, twofa: string, baseUrl: string, country: string, countryCode: string): Promise<UserData> {
    try {
      const xMercyKs = crypto.randomUUID().substring(0, 16);
      const signCode = await this.signKeyV3(username, baseUrl, xMercyKs);

      if (!signCode?.data?.k) {
        throw new RoborockApiError('Failed to obtain sign key for V4 login');
      }

      const api = await this.apiForUser(username, baseUrl);
      const response = await api.post(
        'api/v4/auth/email/login/code',
        new URLSearchParams({
          country: country,
          countryCode: countryCode,
          email: username,
          code: twofa,
          majorVersion: '14',
          minorVersion: '0',
        }).toString(),
        {
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            'x-mercy-ks': xMercyKs,
            'x-mercy-k': signCode.data.k,
            header_clientlang: 'en',
            header_appversion: '4.54.02',
            header_phonesystem: 'iOS',
            header_phonemodel: 'iPhone16,1',
          },
        },
      );
      return this.auth(username, response.data);
    } catch (error) {
      throw extractErrorMessage(error, 'Login with 2FA code (V4) failed');
    }
  }

  /**
   * Signs a key using the V3 API (required for V4 login).
   */
  private async signKeyV3(username: string, baseUrl: string, nonce: string): Promise<SignCodeV3 | undefined> {
    const api = await this.apiForUser(username, baseUrl);
    const response = await api.post(
      'api/v3/key/sign',
      new URLSearchParams({
        s: nonce,
      }).toString(),
    );
    return response.data as SignCodeV3;
  }

  public async getHomeDetails(): Promise<HomeInfo | undefined> {
    if (!this.username || !this.authToken) {
      return undefined;
    }

    const api = await this.getAPIFor(this.username);
    const response = await api.get('api/v1/getHomeDetail');

    const apiResponse: AuthenticateResponse<HomeInfo> = response.data;
    if (!apiResponse.data) {
      throw new Error('Failed to retrieve the home details');
    }
    return apiResponse.data;
  }

  private async getAPIFor(username: string): Promise<AxiosInstance> {
    const urlResult = await this.getUrlByEmail(username);
    return this.apiForUser(username, urlResult.baseUrl);
  }

  private async getUrlByEmail(username: string): Promise<UrlByEmailResult> {
    try {
      const api = await this.apiForUser(username);
      const response = await api.post(
        'api/v1/getUrlByEmail',
        new URLSearchParams({
          email: username,
          needtwostepauth: 'false',
        }).toString(),
      );

      const apiResponse: AuthenticateResponse<BaseUrl> = response.data;
      if (!apiResponse.data) {
        throw new RoborockApiError(`Failed to retrieve base URL: ${apiResponse.msg}`, apiResponse.code, apiResponse.msg);
      }

      this.country = apiResponse.data.country;
      this.countryCode = apiResponse.data.countrycode;

      return {
        baseUrl: apiResponse.data.url,
        country: apiResponse.data.country,
        countryCode: apiResponse.data.countrycode,
      };
    } catch (error) {
      throw extractErrorMessage(error, 'Failed to get URL by email');
    }
  }

  private async apiForUser(username: string, baseUrl = 'https://usiot.roborock.com'): Promise<AxiosInstance> {
    return this.axiosFactory.create({
      baseURL: baseUrl,
      headers: {
        header_clientid: crypto.createHash('md5').update(username).update(this.deviceId).digest('base64'),
        Authorization: this.authToken,
      },
    });
  }

  private auth(username: string, response: AuthenticateResponse<UserData>): UserData {
    const userdata = response.data;
    if (!userdata || !userdata.token) {
      throw new RoborockApiError(`Authentication failed: ${response.msg}`, response.code, response.msg);
    }

    this.loginWithAuthToken(username, userdata.token);
    return userdata;
  }

  private loginWithAuthToken(username: string, token: string): void {
    this.username = username;
    this.authToken = token;
  }
}
