export const HOOSAT_MASS = {
  // Transaction structure overhead (from HTND code)
  // version(2) + input_count(8) + output_count(8) + lockTime(8) +
  // subnetwork(32) + gas(8) + payload_hash(32) + payload_length(8) = 106 bytes
  BaseTxOverhead: 106,

  // Per-input size estimation (from HTND code)
  // outpoint(36) + sig_script_length(8) + signature(~107) + sequence(8) = 159 bytes
  EstimatedInputSize: 159,

  // Per-output size estimation (from HTND code)
  // amount(8) + version(2) + script_length(8) + script(~35) = 53 bytes
  EstimatedOutputSize: 53,

  // Mass calculation weights (from HTND)
  MassPerTxByte: 1,
  MassPerScriptPubKeyByte: 10,
  MassPerSigOp: 1000,

  // Script-only size per output for extra mass calculation (from HTND)
  // version(2) + script(~34) = 36 bytes (НЕ 34!)
  ScriptPubKeyBytesPerOutput: 36,
} as const;
