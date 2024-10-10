declare namespace NodeJS {
  export interface ProcessEnv {
    DATABASE_URL: string;
    jwtKey: string;
    jwtRefreshTokenKey: string;
  }
}
