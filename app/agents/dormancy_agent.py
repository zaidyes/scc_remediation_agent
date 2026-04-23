from app.tools.graph_tools import check_dormancy


class DormancyAgent:
    def __init__(self, config):
        self.config = config

    async def check(self, asset_name: str) -> dict:
        """
        Returns dormancy classification for the asset.
        dormancy_class is one of: ACTIVE, PERIODIC, DORMANT.
        DORMANT assets are candidates for auto-approval.
        """
        return check_dormancy(asset_name)
