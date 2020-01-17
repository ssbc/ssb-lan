export type Discovery = {
  verified: boolean;
  address: string;
};

export type SSBConfig = {
  caps: {
    shs: string;
  };
  lan?: {
    legacy?: boolean;
  };
};
