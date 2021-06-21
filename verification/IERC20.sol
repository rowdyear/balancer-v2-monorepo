pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;
interface IERC20 {

    function myAddress() external view returns (address);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    function mint(address recipient, uint256 amount) external;

    function burn(address recipient, uint256 amount) external;
}