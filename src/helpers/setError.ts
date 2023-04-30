import { StatusCode } from 'hono/utils/http-status';

export interface IErrorSchema {
  code: StatusCode;
  success: boolean;
  message: string;
}

export type TSetErrorCallback<T> = (schema: T) => void;
export type TSetError = (cb: TSetErrorCallback<IErrorSchema>) => IErrorSchema;

const setError: TSetError = (cb) => {
  const obj: IErrorSchema = {
    code: 500,
    success: false,
    message: 'Unknown error',
  };

  cb(obj);
  return obj;
};

export default setError;
