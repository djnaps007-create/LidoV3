// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.25;

import {IPredepositGuarantee} from "./interfaces/IPredepositGuarantee.sol";

abstract contract VaultHub {
    struct VaultConnection {
        address owner;
        uint96 shareLimit;
        uint96 vaultIndex;
        uint48 disconnectInitiatedTs;
        uint16 reserveRatioBP;
        uint16 forcedRebalanceThresholdBP;
        uint16 infraFeeBP;
        uint16 liquidityFeeBP;
        uint16 reservationFeeBP;
        bool beaconChainDepositsPauseIntent;
    }

    struct Report {
        uint104 totalValue;
        int104 inOutDelta;
        uint48 timestamp;
    }

    struct VaultRecord {
        Report report;
        uint96 maxLiabilityShares;
        uint96 liabilityShares;
        uint128 minimalReserve;
        uint128 redemptionShares;
        uint128 cumulativeLidoFees;
        uint128 settledLidoFees;
    }

    function fund(address vault) external payable virtual;
    function withdraw(address vault, address recipient, uint256 amount) external virtual;
    function mintShares(address vault, address recipient, uint256 shares) external virtual;
    function burnShares(address vault, uint256 shares) external virtual;
    function rebalance(address vault, uint256 shares) external virtual;
    function pauseBeaconChainDeposits(address vault) external virtual;
    function resumeBeaconChainDeposits(address vault) external virtual;
    function requestValidatorExit(address vault, bytes calldata pubkeys) external virtual;
    function triggerValidatorWithdrawals(
        address vault,
        bytes calldata pubkeys,
        uint64[] calldata amountsInGwei,
        address refundRecipient
    ) external payable virtual;
    function voluntaryDisconnect(address vault) external virtual;
    function transferVaultOwnership(address vault, address newOwner) external virtual;
    function connectVault(address vault) external virtual;
    function isVaultConnected(address vault) external view virtual returns (bool);
    function latestReport(address vault) external view virtual returns (Report memory);
    function isReportFresh(address vault) external view virtual returns (bool);
    function vaultConnection(address vault) external view virtual returns (VaultConnection memory);
    function liabilityShares(address vault) external view virtual returns (uint256);
    function totalValue(address vault) external view virtual returns (uint256);
    function locked(address vault) external view virtual returns (uint256);
    function obligations(address vault) external view virtual returns (uint256 sharesToBurn, uint256 feesToSettle);
    function healthShortfallShares(address vault) external view virtual returns (uint256);
    function obligationsShortfallValue(address vault) external view virtual returns (uint256);
    function vaultRecord(address vault) external view virtual returns (VaultRecord memory);
    function maxLockableValue(address vault) external view virtual returns (uint256);
    function withdrawableValue(address vault) external view virtual returns (uint256);
    function totalMintingCapacityShares(address vault, int256 deltaValue) external view virtual returns (uint256);
    function collectERC20FromVault(address vault, address token, address recipient, uint256 amount) external virtual;
    function proveUnknownValidatorToPDG(
        address vault,
        IPredepositGuarantee.ValidatorWitness calldata witness
    ) external virtual;
}
