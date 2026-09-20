"""
⚡ Web3 Gas & Calldata Security Inspector - High-Performance API Microservice
Engineered for Telegram Trading Bots, Sniper Bots, and Web3 MEV Relayers.
Author: @Tsai-etc (CashFlow Studio)
License: MIT
"""

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import uvicorn
from core_inspector import CalldataInspector, ChainPricing

app = FastAPI(
    title="Web3 Calldata & Gas Security Inspector API",
    description="High-performance real-time EVM calldata parser, EIP-2028 gas calculator, and phishing heuristic auditor for trading bots.",
    version="1.0.0"
)

class InspectRequest(BaseModel):
    calldata: str = Field(..., description="Hex string starting with 0x representing raw EVM calldata")
    chain: Optional[str] = Field("bsc", description="Target blockchain: bsc, ethereum, polygon, arbitrum")
    gwei: Optional[float] = Field(None, description="Custom gas price in Gwei (optional)")

class InspectResponse(BaseModel):
    success: bool
    data: Dict[str, Any]

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "web3-calldata-inspector", "author": "@Tsai-etc"}

@app.post("/api/v1/inspect", response_model=InspectResponse)
def inspect_calldata(req: InspectRequest):
    hex_str = req.calldata.strip()
    if not hex_str.startswith("0x"):
        hex_str = "0x" + hex_str
        
    chain_key = req.chain.lower()
    if chain_key not in ChainPricing.PRESETS:
        raise HTTPException(status_code=400, detail=f"Unsupported chain: {req.chain}. Allowed: {list(ChainPricing.PRESETS.keys())}")
        
    try:
        raw_bytes = bytes.fromhex(hex_str[2:])
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hexadecimal string.")
        
    gas_stats = CalldataInspector.calculate_intrinsic_gas(raw_bytes)
    pricing = ChainPricing.calculate_tx_cost(
        gas_used=gas_stats["total_gas"],
        chain=chain_key,
        custom_gwei=req.gwei
    )
    parsed = CalldataInspector.parse_selector_and_params(raw_bytes)
    
    return {
        "success": True,
        "data": {
            "gas_metrics": gas_stats,
            "cost_estimation": pricing,
            "security_analysis": {
                "selector": parsed["selector"],
                "signature": parsed["signature_guess"],
                "risk_level": parsed["risk_level"],
                "is_dangerous": parsed["risk_level"] in ("HIGH", "CRITICAL"),
                "warning": parsed.get("warning", ""),
                "decoded_params": parsed["decoded_params"]
            }
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8088)
