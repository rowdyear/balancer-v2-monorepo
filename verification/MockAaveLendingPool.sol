import "./IERC20.sol";
import "pkg/asset-manager-utils/contracts/aave/DataTypes.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

// contract MockAaveLendingPool is ILendingPool {
contract MockAaveLendingPool {
    mapping(address => address) public aTokens;
    address public aum_token;

    function deposit(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16 /*referralCode*/
    ) external {
        IERC20 t = IERC20(aTokens[asset]);
        IERC20 a = IERC20(asset);
        require (aTokens[asset] == aum_token);
        require(t != a);
        t.mint(address(onBehalfOf), amount);
        a.transferFrom(onBehalfOf, address(this), amount);
    }

    function withdraw(
        address asset,
        uint256 amount,
        address to
    ) external returns (uint256) {
        IERC20 t = IERC20(aTokens[asset]);
        IERC20 a = IERC20(asset);
        require (aTokens[asset] == aum_token);
        require(t != a);
        t.burn(to, amount);
        a.transfer(to, amount);
        return amount;
    }

    function getReserveData(
        address /*asset*/
    ) external view returns (DataTypes.ReserveData memory) {
        return
            DataTypes.ReserveData({
                configuration: DataTypes.ReserveConfigurationMap({ data: 0 }),
                liquidityIndex: 0,
                variableBorrowIndex: 0,
                currentLiquidityRate: 0,
                currentVariableBorrowRate: 0,
                currentStableBorrowRate: 0,
                lastUpdateTimestamp: 0,
                aTokenAddress: aum_token, // This is the only relevant field probably
                stableDebtTokenAddress: address(0),
                variableDebtTokenAddress: address(0),
                interestRateStrategyAddress: address(0),
                id: 0
            });
    }
}