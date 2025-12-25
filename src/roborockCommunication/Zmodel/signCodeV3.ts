export interface SignCodeV3 {
  code: string;
  message: string;
  data?: SignCodeV3Data;
}

export interface SignCodeV3Data {
  k: string;
}
