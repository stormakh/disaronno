//! Same fields as Types/Contact.ts.

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Contact {
    /// ID either in lid or jid format (preferred). An empty string stands for a missing `id`.
    pub id: String,
    /// ID in LID format (@lid)
    pub lid: Option<String>,
    /// ID in PN format (@s.whatsapp.net)
    pub phone_number: Option<String>,
    /// name of the contact, you have saved on your WA
    pub name: Option<String>,
    /// name of the contact, the contact has set on their own on WA
    pub notify: Option<String>,
    /// username associated with this contact, when provided by WA
    pub username: Option<String>,
    pub verified_name: Option<String>,
    /// `Some(None)` is null: the default profile picture. `Some(Some("changed"))` means the
    /// profile picture has changed. Any other string is its url.
    pub img_url: Option<Option<String>>,
    pub status: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactField {
    Lid,
    PhoneNumber,
    Name,
    Notify,
    Username,
    VerifiedName,
    ImgUrl,
    Status,
}
impl Contact {
    pub fn new(id: impl Into<String>) -> Contact {
        Contact { id: id.into(), ..Contact::default() }
    }
    /// Same as `Object.assign(self, trimUndefined(o))`.
    pub fn assign(&mut self, o: &Contact) {
        if !o.id.is_empty() {
            self.id = o.id.clone();
        }
        fn set<T: Clone>(a: &mut Option<T>, b: &Option<T>) {
            if b.is_some() {
                *a = b.clone();
            }
        }
        set(&mut self.lid, &o.lid);
        set(&mut self.phone_number, &o.phone_number);
        set(&mut self.name, &o.name);
        set(&mut self.notify, &o.notify);
        set(&mut self.username, &o.username);
        set(&mut self.verified_name, &o.verified_name);
        set(&mut self.img_url, &o.img_url);
        set(&mut self.status, &o.status);
    }
    pub fn clear_field(&mut self, f: ContactField) {
        match f {
            ContactField::Lid => self.lid = None,
            ContactField::PhoneNumber => self.phone_number = None,
            ContactField::Name => self.name = None,
            ContactField::Notify => self.notify = None,
            ContactField::Username => self.username = None,
            ContactField::VerifiedName => self.verified_name = None,
            ContactField::ImgUrl => self.img_url = None,
            ContactField::Status => self.status = None,
        }
    }
    /// Same as `Object.assign(self, update)`, where a key set to `undefined` clears the old value.
    pub fn apply_update(&mut self, u: &ContactUpdate) {
        self.assign(&u.contact);
        for f in &u.undefined {
            self.clear_field(*f);
        }
    }
}
/// `Partial<Contact>`. Fields that are `None` in `contact` are missing keys. `undefined` lists
/// the keys that are present with the value `undefined`, because `Object.assign` copies those.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ContactUpdate {
    pub contact: Contact,
    pub undefined: Vec<ContactField>,
}
impl ContactUpdate {
    pub fn new(contact: Contact) -> ContactUpdate {
        ContactUpdate { contact, undefined: Vec::new() }
    }
    /// Same as `Object.assign(self, o)` for two partial contacts.
    pub fn assign(&mut self, o: &ContactUpdate) {
        self.contact.apply_update(o);
        self.undefined.retain(|f| !field_set(&o.contact, *f));
        for f in &o.undefined {
            if !self.undefined.contains(f) {
                self.undefined.push(*f);
            }
        }
    }
}
fn field_set(c: &Contact, f: ContactField) -> bool {
    match f {
        ContactField::Lid => c.lid.is_some(),
        ContactField::PhoneNumber => c.phone_number.is_some(),
        ContactField::Name => c.name.is_some(),
        ContactField::Notify => c.notify.is_some(),
        ContactField::Username => c.username.is_some(),
        ContactField::VerifiedName => c.verified_name.is_some(),
        ContactField::ImgUrl => c.img_url.is_some(),
        ContactField::Status => c.status.is_some(),
    }
}
impl std::ops::Deref for ContactUpdate {
    type Target = Contact;
    fn deref(&self) -> &Contact {
        &self.contact
    }
}
impl std::ops::DerefMut for ContactUpdate {
    fn deref_mut(&mut self) -> &mut Contact {
        &mut self.contact
    }
}
