class SameDict(dict):
    """
    Class to compare call argument with dict type in mock.assert_called_once_with
    """
    def __eq__(self, other):
        """
        Returns True if other object is dict (or it's subtype) and contains same .items() set
        """
        if not isinstance(other, dict):
            return False

        unmatched_item = set(self.items()) ^ set(other.items())
        return len(unmatched_item) == 0