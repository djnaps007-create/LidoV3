// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.25;

abstract contract LazyOracle {
    struct QuarantineInfo {
        bool isActive;
        uint256 pendingTotalValueIncrease;
        uint256 startTimestamp;
        uint256 endTimestamp;
    }

    function latestReportTimestamp() external view virtual returns (uint256);
    function vaultQuarantine(address vault) external view virtual returns (QuarantineInfo memory);
}
