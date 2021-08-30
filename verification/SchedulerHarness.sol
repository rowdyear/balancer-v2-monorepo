import "pkg/distributors/contracts/RewardsScheduler.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract SchedulerHarness is RewardsScheduler {
    constructor() {}

    function isRewardUinitilized(bytes32 rewardId) external view returns (bool) {
        return _rewards[rewardId].status == RewardStatus.UNINITIALIZED;
    }

    function isRewardPending(bytes32 rewardId) external view returns (bool) {
        return _rewards[rewardId].status == RewardStatus.PENDING;
    }

    function isRewardStarted(bytes32 rewardId) external view returns (bool) {
        return _rewards[rewardId].status == RewardStatus.STARTED;
    }
}