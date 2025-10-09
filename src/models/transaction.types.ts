export interface TransactionInput {
  previousOutpoint: {
    transactionId: string;
    index: number;
  };
  signatureScript: string;
  sequence: string;
  sigOpCount: number;
  utxoEntry?: UtxoEntry; // Optional (for crypto operations)
}

export interface TransactionOutput {
  amount: string;
  scriptPublicKey: {
    version: number;
    scriptPublicKey: string;
  };
}

export interface Transaction {
  version: number;
  inputs: TransactionInput[];
  outputs: TransactionOutput[];
  lockTime: string;
  subnetworkId: string;
  gas: string;
  payload: string;
  fee?: string; // Optional (for TxBuilder)
}

export interface UtxoEntry {
  amount: string;
  scriptPublicKey: {
    script: string;
    version: number;
  };
  blockDaaScore: string;
  isCoinbase: boolean;
}

export interface UtxoForSigning {
  outpoint: {
    transactionId: string;
    index: number;
  };
  utxoEntry: UtxoEntry;
}
