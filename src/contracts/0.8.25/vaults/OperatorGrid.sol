// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.25;

abstract contract OperatorGrid {
    function changeTier(address vault, uint256 tierId, uint256 shareLimit) external virtual returns (bool);
    function syncTier(address vault) external virtual returns (bool);
    function updateVaultShareLimit(address vault, uint256 shareLimit) external virtual returns (bool);
}
