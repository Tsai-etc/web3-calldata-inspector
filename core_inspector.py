"""
Web3 Gas & Calldata Security Inspector - Core Engine
====================================================
A lightweight, zero-dependency EVM calldata decoder, gas estimator,
and security risk heuristic analyzer for BSC, Ethereum, Polygon, and Arbitrum.

Author: CashFlow Studio (@Tsai-etc)
Donation/Sponsorship: 0x322f38636bf6fa64d07af5f481bcb63bc3828731 (BNB Smart Chain BEP20)
"""

import re
from typing import Dict, Any, List, Optional

# Standard ERC-20 / Common DeFi 4-byte Method Signatures
KNOWN_SELECTORS: Dict[str, Dict[str, Any]] = {
    "0xa9059cbb": {
        "name": "transfer(address to, uint256 amount)",
        "method": "transfer",
        "params": [("to", "address"), ("amount", "uint256")],
        "risk_level": "LOW",
        "category": "ERC20"
    },
    "0x095ea7b3": {
        "name": "approve(address spender, uint256 amount)",
        "method": "approve",
        "params": [("spender", "address"), ("amount", "uint256")],
        "risk_level": "MEDIUM",
        "category": "ERC20"
    },
    "0x23b872dd": {
        "name": "transferFrom(address from, address to, uint256 amount)",
        "method": "transferFrom",
        "params": [("from", "address"), ("to", "address"), ("amount", "uint256")],
        "risk_level": "LOW",
        "category": "ERC20"
    },
    "0xd0e30db0": {
        "name": "deposit()",
        "method": "deposit",
        "params": [],
        "risk_level": "LOW",
        "category": "WETH/WBNB"
    },
    "0x2e1a7d4d": {
        "name": "withdraw(uint256 amount)",
        "method": "withdraw",
        "params": [("amount", "uint256")],
        "risk_level": "LOW",
        "category": "WETH/WBNB"
    },
    "0x38ed1739": {
        "name": "swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)",
        "method": "swapExactTokensForTokens",
        "params": [
            ("amountIn", "uint256"),
            ("amountOutMin", "uint256"),
            ("path_offset", "uint256"),
            ("to", "address"),
            ("deadline", "uint256")
        ],
        "risk_level": "MEDIUM",
        "category": "Uniswap/PancakeSwap"
    },
    "0x7ff36ab5": {
        "name": "swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)",
        "method": "swapExactETHForTokens",
        "params": [
            ("amountOutMin", "uint256"),
            ("path_offset", "uint256"),
            ("to", "address"),
            ("deadline", "uint256")
        ],
        "risk_level": "MEDIUM",
        "category": "Uniswap/PancakeSwap"
    },
    "0x18cbafe5": {
        "name": "swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)",
        "method": "swapExactTokensForETH",
        "params": [
            ("amountIn", "uint256"),
            ("amountOutMin", "uint256"),
            ("path_offset", "uint256"),
            ("to", "address"),
            ("deadline", "uint256")
        ],
        "risk_level": "MEDIUM",
        "category": "Uniswap/PancakeSwap"
    },
    "0xbaa2abde": {
        "name": "permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)",
        "method": "permit",
        "params": [
            ("owner", "address"),
            ("spender", "address"),
            ("value", "uint256"),
            ("deadline", "uint256")
        ],
        "risk_level": "HIGH",
        "category": "EIP-2612 Permit"
    }
}

# Chain standard gas pricing defaults (Gwei, Native price in USD)
CHAIN_PROFILES = {
    "bsc": {"name": "BNB Smart Chain (BEP20)", "gas_price_gwei": 3.0, "native_symbol": "BNB", "native_price_usd": 580.0},
    "ethereum": {"name": "Ethereum Mainnet", "gas_price_gwei": 15.0, "native_symbol": "ETH", "native_price_usd": 2700.0},
    "polygon": {"name": "Polygon PoS", "gas_price_gwei": 30.0, "native_symbol": "POL", "native_price_usd": 0.40},
    "arbitrum": {"name": "Arbitrum One", "gas_price_gwei": 0.1, "native_symbol": "ETH", "native_price_usd": 2700.0}
}

MAX_UINT256 = 2**256 - 1
UNLIMITED_ALLOWANCE_THRESHOLD = 2**255


def sanitize_hex(hex_str: str) -> str:
    cleaned = hex_str.strip()
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    return cleaned.lower()


def decode_calldata(raw_calldata: str) -> Dict[str, Any]:
    """
    Decodes raw hex calldata, extracts function selector, matches known ABI signatures,
    decodes standard parameters (addresses, uint256 amounts), and runs security heuristics.
    """
    hex_clean = sanitize_hex(raw_calldata)
    if len(hex_clean) < 8:
        if len(hex_clean) == 0:
            return {
                "success": True,
                "type": "NATIVE_TRANSFER",
                "selector": "0x",
                "function_name": "Native Transfer (ETH/BNB)",
                "parameters": {},
                "risk_assessment": {
                    "level": "SAFE",
                    "warnings": []
                }
            }
        return {
            "success": False,
            "error": "Calldata must contain at least 4 bytes (8 hex characters) for function selector."
        }

    selector = "0x" + hex_clean[:8]
    payload = hex_clean[8:]
    
    # Split payload into 32-byte (64 hex char) words
    words = [payload[i:i+64] for i in range(0, len(payload), 64)]
    
    parsed_info: Dict[str, Any] = {
        "success": True,
        "selector": selector,
        "raw_length_bytes": len(hex_clean) // 2,
        "parameter_words_count": len(words),
        "risk_assessment": {
            "level": "LOW",
            "warnings": []
        }
    }

    if selector in KNOWN_SELECTORS:
        known = KNOWN_SELECTORS[selector]
        parsed_info["function_name"] = known["name"]
        parsed_info["method"] = known["method"]
        parsed_info["category"] = known["category"]
        parsed_info["default_risk"] = known["risk_level"]

        decoded_params = {}
        for idx, (param_name, param_type) in enumerate(known["params"]):
            if idx < len(words):
                word = words[idx]
                if param_type == "address":
                    # address is rightmost 20 bytes (40 hex chars)
                    addr = "0x" + word[-40:]
                    decoded_params[param_name] = addr
                elif param_type == "uint256":
                    val = int(word, 16) if word else 0
                    decoded_params[param_name] = val
                    if val >= UNLIMITED_ALLOWANCE_THRESHOLD:
                        decoded_params[param_name + "_human"] = "UNLIMITED (Max uint256)"
                else:
                    decoded_params[param_name] = "0x" + word
        
        parsed_info["parameters"] = decoded_params

        # Security Heuristics
        warnings: List[str] = []
        risk_level = known["risk_level"]

        # Check for Unlimited Approval Risk
        if known["method"] == "approve":
            amount = decoded_params.get("amount", 0)
            if amount >= UNLIMITED_ALLOWANCE_THRESHOLD:
                risk_level = "HIGH"
                warnings.append(
                    f"Unlimited token approval detected for spender {decoded_params.get('spender', 'UNKNOWN')}. "
                    "Ensure the spender address is a verified router/vault contract, otherwise your wallet can be drained."
                )
        
        # Check for Permit signature exploit vectors
        if known["method"] == "permit":
            risk_level = "CRITICAL"
            warnings.append(
                "EIP-2612 Permit call detected! Phishing sites often trick users into signing permits "
                "to bypass MetaMask standard transfer prompts and drain tokens without gas."
            )

        parsed_info["risk_assessment"]["level"] = risk_level
        parsed_info["risk_assessment"]["warnings"] = warnings

    else:
        parsed_info["function_name"] = f"Unknown Method ({selector})"
        parsed_info["method"] = "unknown"
        parsed_info["category"] = "Custom / Unverified Contract"
        parsed_info["parameters"] = {f"word_{i}": "0x" + w for i, w in enumerate(words)}
        parsed_info["risk_assessment"]["level"] = "MEDIUM"
        parsed_info["risk_assessment"]["warnings"] = [
            f"Selector {selector} is not in the standard ERC20/DeFi registry. Exercise caution before signing transactions on unverified contracts."
        ]

    return parsed_info


def calculate_gas_costs(calldata_hex: str, base_execution_gas: int = 45000, chain_id: str = "bsc") -> Dict[str, Any]:
    """
    Computes accurate intrinsic gas and estimated execution gas according to EIP-2028:
    - 4 gas per zero byte
    - 16 gas per non-zero byte
    - 21,000 base transaction gas
    """
    hex_clean = sanitize_hex(calldata_hex)
    raw_bytes = bytes.fromhex(hex_clean) if hex_clean else b""
    
    zero_bytes = sum(1 for b in raw_bytes if b == 0)
    nonzero_bytes = len(raw_bytes) - zero_bytes
    
    intrinsic_calldata_gas = (zero_bytes * 4) + (nonzero_bytes * 16)
    total_intrinsic_gas = 21000 + intrinsic_calldata_gas
    total_estimated_gas = total_intrinsic_gas + base_execution_gas

    profile = CHAIN_PROFILES.get(chain_id.lower(), CHAIN_PROFILES["bsc"])
    gas_price_gwei = profile["gas_price_gwei"]
    native_price_usd = profile["native_price_usd"]
    native_symbol = profile["native_symbol"]

    # Total native fee = gas * gas_price_gwei * 1e-9
    fee_native = total_estimated_gas * gas_price_gwei * 1e-9
    fee_usd = fee_native * native_price_usd

    return {
        "chain": profile["name"],
        "native_symbol": native_symbol,
        "calldata_length_bytes": len(raw_bytes),
        "zero_bytes_count": zero_bytes,
        "nonzero_bytes_count": nonzero_bytes,
        "intrinsic_calldata_gas": intrinsic_calldata_gas,
        "total_intrinsic_gas": total_intrinsic_gas,
        "estimated_execution_gas": base_execution_gas,
        "total_estimated_gas": total_estimated_gas,
        "gas_price_gwei": gas_price_gwei,
        "estimated_fee_native": round(fee_native, 6),
        "estimated_fee_usd": round(fee_usd, 4)
    }
