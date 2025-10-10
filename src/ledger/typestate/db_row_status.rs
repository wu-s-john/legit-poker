/// Typestate marker that captures whether a database-backed record has been
/// persisted yet.
pub trait DbRowStatus {
    type DbId;
    fn id(&self) -> Self::DbId;
}

#[derive(Debug, Clone, Copy)]
pub struct NotSaved;

#[derive(Debug, Clone, Copy)]
pub struct Saved<Id> {
    pub id: Id,
}

#[derive(Debug, Clone, Copy)]
pub struct MaybeSaved<Id> {
    pub id: Option<Id>,
}

impl DbRowStatus for NotSaved {
    type DbId = ();

    fn id(&self) -> Self::DbId {
        ()
    }
}

impl<Id: Copy> DbRowStatus for Saved<Id> {
    type DbId = Id;

    fn id(&self) -> Self::DbId {
        self.id
    }
}

impl<Id: Copy> DbRowStatus for MaybeSaved<Id> {
    type DbId = Option<Id>;

    fn id(&self) -> Self::DbId {
        self.id
    }
}
