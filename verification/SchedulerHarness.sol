import "pkg/distributors/contracts/RewardsScheduler.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract SchedulerHarness is RewardsScheduler {
    constructor() {}

    function Harness_isRewardUinitilized(bytes32 rewardId) external view returns (bool) {
        return _rewards[rewardId].status == RewardStatus.UNINITIALIZED;
    }

    function Harness_isRewardPending(bytes32 rewardId) external view returns (bool) {
        return _rewards[rewardId].status == RewardStatus.PENDING;
    }

    function Harness_isRewardStarted(bytes32 rewardId) external view returns (bool) {
        return _rewards[rewardId].status == RewardStatus.STARTED;
    }

    function Harness_getRewardStartTime(bytes32 rewardId) external view returns (uint256) {
        return _rewards[rewardId].startTime;
    }

    function Harness_startReward(bytes32 rewardId) external {
        bytes32[] memory rewardIds = new bytes32[](1);
        rewardIds[0] = rewardId;
        startRewards(rewardIds);
    }
}