import "./IERC20.sol";

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
}