//! This crate contains the foreground portion of our VPN plugin app.
//!
//! We use XAML programmatically to generate the UI, see [`ui`].

#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
// Windows naming conventions
// The `implement(extend ...)` macro of windows 0.28 expands to an unused `Box::from_raw` result.
#![allow(unused_must_use)]

mod ui;

use windows::{
    self as Windows,
    core::*,
    ApplicationModel::Activation::LaunchActivatedEventArgs,
    Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED},
    UI::Xaml::{Application, ApplicationInitializationCallback, Window},
};

/// Encapsulates our app and overrides the relevant lifecycle management methods.
#[implement(
    extend Windows::UI::Xaml::Application,
    override OnLaunched
)]
struct App;

impl App {
    /// This method get invoked when the app is initially launched.
    fn OnLaunched(&self, _args: &Option<LaunchActivatedEventArgs>) -> Result<()> {
        let window = Window::Current()?;
        window.SetContent(ui::build()?)?;
        window.Activate()
    }
}

fn main() -> Result<()> {
    // We must initialize a COM MTA before initializing the rest of the App
    unsafe {
        CoInitializeEx(std::ptr::null_mut(), COINIT_MULTITHREADED)?;
    }

    // `Windows::UI::Xaml::Application` (which `App` derives from) is responsible for setting up
    // the CoreWindow and Dispatcher for us before calling our overridden OnLaunched/OnActivated.
    Application::Start(ApplicationInitializationCallback::new(|_| {
        App.new().map(|_| ())
    }))
}
