class ACLDeniedError(Exception): pass
class DocumentNotExistError(Exception):
    def __init__(self, docid):
        self.docid = docid
        super().__init__(docid)
    def __str__(self):
        return f"document {self.docid} does not exist"
class RevisionNotExistError(Exception):
    def __init__(self, rev):
        self.rev = rev
        super().__init__(rev)
    def __str__(self):
        return f"r{self.rev} does not exist"
class CannotRevertRevisionError(Exception):
    def __init__(self, rev):
        self.rev = rev
        super().__init__(rev)
    def __str__(self):
        return f"Cannot revert to r{self.rev}"