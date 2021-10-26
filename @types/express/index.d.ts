declare namespace Express {
  export interface Request {
    authn: any;
  }
  export interface Response {
    sign: function;
    resetCookie: function;
    issue: function;
    issueTokens: function;
    issueRefreshCookie: function;
  }
}
