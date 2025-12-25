import { RoborockAuthenticateApi } from '../../../roborockCommunication/RESTAPI/roborockAuthenticateApi';

describe('RoborockAuthenticateApi', () => {
  let mockLogger: any;
  let mockAxiosFactory: any;
  let mockAxiosInstance: any;
  let api: any;

  beforeEach(() => {
    mockLogger = { info: jest.fn(), error: jest.fn(), debug: jest.fn() };
    mockAxiosInstance = {
      post: jest.fn(),
      get: jest.fn(),
    };
    mockAxiosFactory = {
      create: jest.fn(() => mockAxiosInstance),
    };
    api = new RoborockAuthenticateApi(mockLogger, mockAxiosFactory);
  });

  it('should initialize deviceId, logger, axiosFactory', () => {
    expect(api.logger).toBe(mockLogger);
    expect(api.axiosFactory).toBe(mockAxiosFactory);
    expect(typeof api['deviceId']).toBe('string');
  });

  it('loginWithUserData should call loginWithAuthToken and return userData', async () => {
    const spy = jest.spyOn(api as any, 'loginWithAuthToken');
    const userData = { token: 'abc', other: 'data' };
    const result = await api.loginWithUserData('user', userData);
    expect(spy).toHaveBeenCalledWith('user', 'abc');
    expect(result).toBe(userData);
  });

  it('requestCode should call getUrlByEmail and send code request', async () => {
    const urlResult = { baseUrl: 'http://base.url', country: 'US', countryCode: 'us' };
    jest.spyOn(api as any, 'getUrlByEmail').mockResolvedValue(urlResult);
    jest.spyOn(api as any, 'apiForUser').mockResolvedValue(mockAxiosInstance);
    mockAxiosInstance.post.mockResolvedValue({ data: {} });

    const result = await api.requestCode('user');
    expect(result).toEqual(urlResult);
    expect(api['getUrlByEmail']).toHaveBeenCalledWith('user');
    expect(mockAxiosInstance.post).toHaveBeenCalledWith(
      'api/v4/email/code/send',
      expect.any(String),
      expect.objectContaining({
        headers: expect.objectContaining({
          'content-type': 'application/x-www-form-urlencoded',
          header_clientlang: 'en',
        }),
      }),
    );
  });

  it('loginWithCode should call auth and return userData', async () => {
    const userData = { token: 'tok', other: 'data' };
    const response = { data: { data: userData } };
    jest.spyOn(api as any, 'apiForUser').mockResolvedValue(mockAxiosInstance);
    mockAxiosInstance.post.mockResolvedValue(response);
    jest.spyOn(api as any, 'auth').mockReturnValue(userData);

    const result = await api.loginWithCode('user', '123456', 'http://base.url');
    expect(result).toBe(userData);
    expect(mockAxiosInstance.post).toHaveBeenCalledWith('api/v1/login', expect.stringContaining('verifycode=123456'));
    expect(api['auth']).toHaveBeenCalledWith('user', response.data);
  });

  it('loginWithCode should throw error if token missing', async () => {
    const response = { data: { data: null, msg: 'fail', code: 401 } };
    jest.spyOn(api as any, 'apiForUser').mockResolvedValue(mockAxiosInstance);
    mockAxiosInstance.post.mockResolvedValue(response);
    jest.spyOn(api as any, 'auth').mockImplementation(() => {
      throw new Error('Authentication failed: fail code: 401');
    });

    await expect(api.loginWithCode('user', '123456', 'http://base.url')).rejects.toThrow('Authentication failed: fail code: 401');
  });

  it('loginWithCodeV4 should call signKeyV3 and auth', async () => {
    const userData = { token: 'tok', other: 'data' };
    const signCodeResponse = { data: { k: 'signkey' } };
    const loginResponse = { data: { data: userData } };
    jest.spyOn(api as any, 'signKeyV3').mockResolvedValue(signCodeResponse);
    jest.spyOn(api as any, 'apiForUser').mockResolvedValue(mockAxiosInstance);
    mockAxiosInstance.post.mockResolvedValue(loginResponse);
    jest.spyOn(api as any, 'auth').mockReturnValue(userData);

    const result = await api.loginWithCodeV4('user', '123456', 'http://base.url', 'US', 'us');
    expect(result).toBe(userData);
    expect(api['signKeyV3']).toHaveBeenCalled();
    expect(mockAxiosInstance.post).toHaveBeenCalledWith(
      'api/v4/auth/email/login/code',
      expect.any(String),
      expect.objectContaining({
        headers: expect.objectContaining({
          'x-mercy-k': 'signkey',
        }),
      }),
    );
  });

  it('loginWithCodeV4 should throw error if signKeyV3 fails', async () => {
    jest.spyOn(api as any, 'signKeyV3').mockResolvedValue({ data: null });

    await expect(api.loginWithCodeV4('user', '123456', 'http://base.url', 'US', 'us')).rejects.toThrow('Failed to obtain sign key for V4 login');
  });

  it('getHomeDetails should return undefined if username/authToken missing', async () => {
    api['username'] = undefined;
    api['authToken'] = undefined;
    const result = await api.getHomeDetails();
    expect(result).toBeUndefined();
  });

  it('getHomeDetails should throw error if response.data missing', async () => {
    api['username'] = 'user';
    api['authToken'] = 'tok';
    jest.spyOn(api as any, 'getAPIFor').mockResolvedValue(mockAxiosInstance);
    mockAxiosInstance.get.mockResolvedValue({ data: { data: null } });

    await expect(api.getHomeDetails()).rejects.toThrow('Failed to retrieve the home details');
  });

  it('getHomeDetails should return HomeInfo if present', async () => {
    api['username'] = 'user';
    api['authToken'] = 'tok';
    const homeInfo = { home: 'info' };
    jest.spyOn(api as any, 'getAPIFor').mockResolvedValue(mockAxiosInstance);
    mockAxiosInstance.get.mockResolvedValue({ data: { data: homeInfo } });

    const result = await api.getHomeDetails();
    expect(result).toBe(homeInfo);
  });

  it('getUrlByEmail should throw error if response.data missing', async () => {
    jest.spyOn(api as any, 'apiForUser').mockResolvedValue(mockAxiosInstance);
    mockAxiosInstance.post.mockResolvedValue({ data: { data: null, msg: 'fail' } });

    await expect(api['getUrlByEmail']('user')).rejects.toThrow('Failed to retrieve base URL: fail');
  });

  it('getUrlByEmail should return UrlByEmailResult if present', async () => {
    jest.spyOn(api as any, 'apiForUser').mockResolvedValue(mockAxiosInstance);
    mockAxiosInstance.post.mockResolvedValue({ data: { data: { url: 'http://base.url', country: 'US', countrycode: 'us' } } });

    const result = await api['getUrlByEmail']('user');
    expect(result).toEqual({ baseUrl: 'http://base.url', country: 'US', countryCode: 'us' });
  });

  it('apiForUser should create AxiosInstance with correct headers', async () => {
    const username = 'user';
    const baseUrl = 'http://base.url';
    const spy = jest.spyOn(mockAxiosFactory, 'create');
    await api['apiForUser'](username, baseUrl);
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        baseURL: baseUrl,
        headers: expect.objectContaining({
          header_clientid: expect.any(String),
          Authorization: undefined,
        }),
      }),
    );
  });

  it('auth should call loginWithAuthToken and return userData', () => {
    const spy = jest.spyOn(api as any, 'loginWithAuthToken');
    const response = { data: { token: 'tok', other: 'data' }, msg: '', code: 0 };
    const result = api['auth']('user', response);
    expect(spy).toHaveBeenCalledWith('user', 'tok');
    expect(result).toBe(response.data);
  });

  it('auth should throw error if token missing', () => {
    const response = { data: null, msg: 'fail', code: 401 };
    expect(() => api['auth']('user', response)).toThrow('Authentication failed: fail');
  });

  it('loginWithAuthToken should set username and authToken', () => {
    api['loginWithAuthToken']('user', 'tok');
    expect(api['username']).toBe('user');
    expect(api['authToken']).toBe('tok');
  });
});
