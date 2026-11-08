//! Same types as Types/Label.ts and Types/LabelAssociation.ts.

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Label {
    /// Label uniq ID
    pub id: String,
    /// Label name
    pub name: String,
    /// Label color ID
    pub color: i32,
    /// Is label has been deleted
    pub deleted: bool,
    /// WhatsApp has 5 predefined labels (New customer, New order & etc)
    pub predefined_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct LabelActionBody {
    pub id: String,
    pub name: Option<String>,
    pub color: Option<i32>,
    pub deleted: Option<bool>,
    pub predefined_id: Option<i32>,
}
/// WhatsApp has 20 predefined colors
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LabelColor {
    Color1 = 0,
    Color2,
    Color3,
    Color4,
    Color5,
    Color6,
    Color7,
    Color8,
    Color9,
    Color10,
    Color11,
    Color12,
    Color13,
    Color14,
    Color15,
    Color16,
    Color17,
    Color18,
    Color19,
    Color20,
}
/// Association type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LabelAssociationType {
    Chat,
    Message,
}
impl LabelAssociationType {
    pub fn as_str(self) -> &'static str {
        match self {
            LabelAssociationType::Chat => "label_jid",
            LabelAssociationType::Message => "label_message",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatLabelAssociation {
    pub chat_id: String,
    pub label_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageLabelAssociation {
    pub chat_id: String,
    pub message_id: String,
    pub label_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabelAssociation {
    Chat(ChatLabelAssociation),
    Message(MessageLabelAssociation),
}
impl LabelAssociation {
    /// The `type` field.
    pub fn kind(&self) -> LabelAssociationType {
        match self {
            LabelAssociation::Chat(_) => LabelAssociationType::Chat,
            LabelAssociation::Message(_) => LabelAssociationType::Message,
        }
    }
}
/// Body for add/remove chat label association action
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatLabelAssociationActionBody {
    pub label_id: String,
}
/// body for add/remove message label association action
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageLabelAssociationActionBody {
    pub label_id: String,
    pub message_id: String,
}
