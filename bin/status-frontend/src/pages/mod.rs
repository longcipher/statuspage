//! Page components for the StatusPage CSR frontend.

mod home;
mod incidents;
mod login;
mod not_found;
mod public_status_page;
mod settings;
mod status_page_detail;
mod status_pages;
mod target_detail;
mod targets;

pub use home::HomePage;
pub use incidents::IncidentListPage;
pub use login::LoginPage;
pub use not_found::NotFoundPage;
pub use public_status_page::PublicStatusPage;
pub use settings::SettingsPage;
pub use status_page_detail::StatusPageDetailPage;
pub use status_pages::StatusPageListPage;
pub use target_detail::TargetDetailPage;
pub use targets::TargetsListPage;
