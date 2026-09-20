"""
Unit Test Suite for Web3 Gas & Calldata Security Inspector
==========================================================
"""

import unittest
from core_inspector import (
    sanitize_hex,
    decode_calldata,
    calculate_gas_costs,
    MAX_UINT256
)


class TestCalldataInspector(unittest.TestCase):

    def test_sanitize_hex(self):
        self.assertEqual(sanitize_hex("0x1234abcd"), "1234abcd")
        self.assertEqual(sanitize_hex("  0XABCDEF  "), "abcdef")
        self.assertEqual(sanitize_hex("deadbeef"), "deadbeef")

    def test_native_transfer(self):
        result = decode_calldata("")
        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "NATIVE_TRANSFER")
        self.assertEqual(result["risk_assessment"]["level"], "SAFE")

    def test_erc20_transfer(self):
        # transfer(0x322f38636bf6fa64d07af5f481bcb63bc3828731, 1000000000000000000)
        # selector: a9059cbb
        # addr word: 000000000000000000000000322f38636bf6fa64d07af5f481bcb63bc3828731
        # amount word: 0000000000000000000000000000000000000000000000000de0b6b3a7640000 (1e18)
        calldata = (
            "0xa9059cbb"
            "000000000000000000000000322f38636bf6fa64d07af5f481bcb63bc3828731"
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
        )
        res = decode_calldata(calldata)
        self.assertTrue(res["success"])
        self.assertEqual(res["selector"], "0xa9059cbb")
        self.assertEqual(res["method"], "transfer")
        self.assertEqual(res["parameters"]["to"], "0x322f38636bf6fa64d07af5f481bcb63bc3828731")
        self.assertEqual(res["parameters"]["amount"], 1000000000000000000)
        self.assertEqual(res["risk_assessment"]["level"], "LOW")

    def test_erc20_unlimited_approve(self):
        # approve(spender, MAX_UINT256)
        # selector: 095ea7b3
        calldata = (
            "0x095ea7b3"
            "0000000000000000000000001111111254fb6c44bac0bed2854e76f90643097d"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        res = decode_calldata(calldata)
        self.assertTrue(res["success"])
        self.assertEqual(res["method"], "approve")
        self.assertEqual(res["risk_assessment"]["level"], "HIGH")
        self.assertTrue(len(res["risk_assessment"]["warnings"]) > 0)
        self.assertIn("Unlimited token approval", res["risk_assessment"]["warnings"][0])

    def test_permit_critical_alert(self):
        # permit selector: baa2abde
        calldata = "0xbaa2abde" + "00" * 32 * 4
        res = decode_calldata(calldata)
        self.assertEqual(res["risk_assessment"]["level"], "CRITICAL")
        self.assertIn("Permit call detected", res["risk_assessment"]["warnings"][0])

    def test_gas_calculation_eip2028(self):
        # 4 zero bytes, 4 non-zero bytes
        # raw bytes: 00 00 00 00 01 02 03 04 -> 4 zeros * 4 = 16, 4 nonzero * 16 = 64. Total calldata = 80.
        hex_data = "0000000001020304"
        gas_info = calculate_gas_costs(hex_data, base_execution_gas=10000, chain_id="bsc")
        self.assertEqual(gas_info["calldata_length_bytes"], 8)
        self.assertEqual(gas_info["zero_bytes_count"], 4)
        self.assertEqual(gas_info["nonzero_bytes_count"], 4)
        self.assertEqual(gas_info["intrinsic_calldata_gas"], 80)
        self.assertEqual(gas_info["total_intrinsic_gas"], 21080)
        self.assertEqual(gas_info["total_estimated_gas"], 31080)
        self.assertIn("BNB", gas_info["native_symbol"])


if __name__ == "__main__":
    unittest.main()
