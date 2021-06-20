import "./ERC20.sol";

// contract MockAaveLendingPool is ILendingPool {
contract MockAaveLendingPool {
    mapping(address => address) public aTokens;

    function deposit(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16 /*referralCode*/
    ) external {
        ERC20 t = ERC20(aTokens[asset]);
        ERC20 a = ERC20(asset);
        // require(t != a);
        t.mint(address(onBehalfOf), amount);
        a.transferFrom(onBehalfOf, address(this), amount);
    }

    function withdraw(
        address asset,
        uint256 amount,
        address to
    ) external returns (uint256) {
        ERC20 t = ERC20(aTokens[asset]);
        ERC20 a = ERC20(asset); 
        // require(t != a);
        t.burn(to, amount);
        a.transfer(to, amount);
        return amount;
    }
}