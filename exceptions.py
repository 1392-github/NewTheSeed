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
class NoteRequiredError(Exception): pass
class ACLGroupNoteRequiredError(Exception): pass
class ACLGroupPermissionDeniedError(Exception): pass
class ACLGroupConfigError(Exception):
    def __init__(self, name, value):
        self.name = name
        self.value = value
        super().__init__(name, value)
    def __str__(self):
        return f"{self.name} is {self.value}"
class InvalidCIDRError(ValueError): pass
class ACLGroupAlreadyExistsError(Exception): pass
class ACLGroupNotExistsError(Exception):
    def __init__(self, id):
        self.id = id
        super().__init__(id)
    def __str__(self):
        return f"ACLGroup {self.id} does not exist"
class ACLGroupElementNotExistsError(Exception):
    def __init__(self, id):
        self.id = id
        super().__init__(id)
    def __str__(self):
        return f"ACLGroup Element #{self.id} does not exist"
class MaximumTimeExceedError(Exception): pass