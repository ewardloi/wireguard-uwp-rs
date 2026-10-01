//! The profile editor page.
//!
//! Profiles live in Windows' VPN list (the same list Settings shows). A profile is
//! created there (Settings > Network & internet > VPN, provider "WireGuard VPN");
//! this page lists the ones backed by our plugin and lets the user load settings
//! from a `.conf` file and save them to Windows. All parsing and validation is
//! done by [`wireguard_config`]; this file moves strings between XAML controls
//! and Windows' `VpnManagementAgent`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use windows::{
    core::*,
    ApplicationModel::{
        DataTransfer::{Clipboard, DataPackage},
        Package,
    },
    Foundation::{AsyncOperationCompletedHandler, AsyncStatus, PropertyValue},
    Networking::Vpn::{VpnManagementAgent, VpnPlugInProfile},
    Storage::{FileIO, Pickers::FileOpenPicker, StorageFile},
    UI::Core::{CoreDispatcher, CoreDispatcherPriority, DispatchedHandler},
    UI::Xaml::{
        Controls::{
            Button, ComboBox, Orientation, Page, PasswordBox, ScrollBarVisibility, ScrollViewer,
            SelectionChangedEventHandler, StackPanel, TextBlock, TextBox,
        },
        RoutedEventHandler, TextWrapping, Thickness, Visibility,
    },
};
use wireguard_config::form::{server_from_uri_host, Profile, ProfileForm};
use wireguard_config::{parse_wg_quick, WireGuardConfig};

const NO_PROFILES: &str = "No WireGuard profiles found. Add one in Windows Settings > Network & \
internet > VPN (VPN provider: WireGuard VPN), then press Refresh.";

/// Build the page shown in the main window.
pub fn build() -> Result<Page> {
    let controls = Controls::new()?;
    let page = controls.layout()?;

    let controller = Rc::new(Controller {
        c: controls,
        agent: VpnManagementAgent::new()?,
        profiles: RefCell::new(Vec::new()),
        busy: Cell::new(false),
    });
    controller.wire_events()?;
    controller.report(controller.refresh(None));

    let root = Page::new()?;
    root.SetContent(page)?;
    Ok(root)
}

fn thickness(all: f64) -> Thickness {
    Thickness {
        Left: all,
        Top: all,
        Right: all,
        Bottom: all,
    }
}

fn heading(text: &str) -> Result<TextBlock> {
    let block = TextBlock::new()?;
    block.SetText(text)?;
    block.SetFontSize(20.)?;
    block.SetMargin(Thickness {
        Left: 0.,
        Top: 16.,
        Right: 0.,
        Bottom: 0.,
    })?;
    Ok(block)
}

fn text_box(header: &str, placeholder: &str) -> Result<TextBox> {
    let control = TextBox::new()?;
    control.SetHeader(PropertyValue::CreateString(header)?)?;
    control.SetPlaceholderText(placeholder)?;
    Ok(control)
}

fn secret_box(header: &str, placeholder: &str) -> Result<PasswordBox> {
    let control = PasswordBox::new()?;
    control.SetHeader(PropertyValue::CreateString(header)?)?;
    control.SetPlaceholderText(placeholder)?;
    Ok(control)
}

fn button(label: &str) -> Result<Button> {
    let control = Button::new()?;
    control.SetContent(PropertyValue::CreateString(label)?)?;
    Ok(control)
}

/// All the controls on the page.
struct Controls {
    selector: ComboBox,
    editor: StackPanel,
    name: TextBox,
    server: TextBox,
    port: TextBox,
    private_key: PasswordBox,
    address: TextBox,
    dns: TextBox,
    search_domains: TextBox,
    mtu: TextBox,
    public_key: TextBox,
    preshared_key: PasswordBox,
    allowed_ips: TextBox,
    excluded_ips: TextBox,
    keepalive: TextBox,
    load_conf: Button,
    refresh: Button,
    copy_ps: Button,
    status: TextBlock,
}

impl Controls {
    fn new() -> Result<Self> {
        let selector = ComboBox::new()?;
        selector.SetHeader(PropertyValue::CreateString("Profile")?)?;

        let editor = StackPanel::new()?;
        editor.SetSpacing(10.)?;
        editor.SetVisibility(Visibility::Collapsed)?;

        let name = text_box("Profile name (set in Windows Settings)", "")?;
        name.SetIsReadOnly(true)?;

        let status = TextBlock::new()?;
        status.SetTextWrapping(TextWrapping::Wrap)?;

        Ok(Self {
            selector,
            editor,
            name,
            server: text_box("Server", "vpn.example.com")?,
            port: text_box("Server port", "51820")?,
            private_key: secret_box("Private key", "base64")?,
            address: text_box("Address (comma separated)", "10.0.0.2/32, fd00::2/128")?,
            dns: text_box("DNS servers (optional)", "1.1.1.1, 9.9.9.9")?,
            search_domains: text_box("DNS search domains (optional)", "corp.example.com")?,
            mtu: text_box("MTU (optional, 576-1500, default 1500)", "1420")?,
            public_key: text_box("Server public key", "base64")?,
            preshared_key: secret_box("Preshared key (optional)", "base64")?,
            allowed_ips: text_box("Allowed IPs", "0.0.0.0/0, ::/0")?,
            excluded_ips: text_box("Excluded IPs (optional)", "192.168.1.0/24")?,
            keepalive: text_box("Persistent keepalive, seconds (optional)", "25")?,
            load_conf: button("Load .conf")?,
            refresh: button("Refresh")?,
            copy_ps: button("Copy PowerShell")?,
            status,
        })
    }

    /// Stack the controls into a scrollable page.
    fn layout(&self) -> Result<ScrollViewer> {
        let panel = StackPanel::new()?;
        panel.SetSpacing(10.)?;
        panel.SetMaxWidth(560.)?;
        panel.SetPadding(thickness(24.))?;

        let title = TextBlock::new()?;
        title.SetText("WireGuard")?;
        title.SetFontSize(32.)?;

        let editor = self.editor.Children()?;
        editor.Append(&self.name)?;
        editor.Append(&self.server)?;
        editor.Append(&self.port)?;
        editor.Append(&heading("Interface")?)?;
        editor.Append(&self.private_key)?;
        editor.Append(&self.address)?;
        editor.Append(&self.dns)?;
        editor.Append(&self.search_domains)?;
        editor.Append(&self.mtu)?;
        editor.Append(&heading("Peer")?)?;
        editor.Append(&self.public_key)?;
        editor.Append(&self.preshared_key)?;
        editor.Append(&self.allowed_ips)?;
        editor.Append(&self.excluded_ips)?;
        editor.Append(&self.keepalive)?;
        editor.Append(&self.copy_ps)?;

        let toolbar = StackPanel::new()?;
        toolbar.SetOrientation(Orientation::Horizontal)?;
        toolbar.SetSpacing(8.)?;
        let toolbar_children = toolbar.Children()?;
        toolbar_children.Append(&self.refresh)?;
        toolbar_children.Append(&self.load_conf)?;

        let children = panel.Children()?;
        children.Append(&title)?;
        children.Append(&self.selector)?;
        children.Append(&toolbar)?;
        children.Append(&self.editor)?;
        children.Append(&self.status)?;

        let scroll = ScrollViewer::new()?;
        scroll.SetVerticalScrollBarVisibility(ScrollBarVisibility::Auto)?;
        scroll.SetContent(&panel)?;
        Ok(scroll)
    }
}

struct Controller {
    c: Controls,
    agent: VpnManagementAgent,
    /// The Windows profiles that belong to this plugin, in selector order.
    profiles: RefCell<Vec<VpnPlugInProfile>>,
    /// Set while we change controls ourselves so their change events are ignored.
    busy: Cell<bool>,
}

impl Controller {
    fn wire_events(self: &Rc<Self>) -> Result<()> {
        let this = self.clone();
        self.c
            .selector
            .SelectionChanged(SelectionChangedEventHandler::new(move |_, _| {
                if !this.busy.get() {
                    this.report(this.on_select());
                }
                Ok(())
            }))?;

        let click = |action: fn(&Controller) -> Result<()>, this: &Rc<Self>| {
            let this = this.clone();
            RoutedEventHandler::new(move |_, _| {
                this.report(action(&*this));
                Ok(())
            })
        };
        self.c.refresh.Click(click(Controller::reload, self))?;
        self.c
            .copy_ps
            .Click(click(Controller::copy_powershell, self))?;
        let this = self.clone();
        self.c
            .load_conf
            .Click(RoutedEventHandler::new(move |_, _| {
                this.report(this.load_conf());
                Ok(())
            }))?;
        Ok(())
    }

    /// Show the outcome of an operation; failures go to the status line.
    fn report(&self, result: Result<()>) {
        if let Err(err) = result {
            let _ = self.set_status(&format!("Error: {}", err.message()));
        }
    }

    fn set_status(&self, text: &str) -> Result<()> {
        self.c.status.SetText(text)
    }

    /// Reload the profiles from Windows and select `select` (or the first one).
    ///
    /// The async calls are awaited with `.get()`: they are quick local calls into the VPN
    /// platform, and it keeps the event handlers simple.
    fn refresh(&self, select: Option<&str>) -> Result<()> {
        let family = Package::Current()?.Id()?.FamilyName()?;
        let all = self.agent.GetProfilesAsync()?.get()?;

        let mut ours = Vec::new();
        for i in 0..all.Size()? {
            // Native (IKEv2, SSTP...) profiles fail this cast and are skipped.
            if let Ok(profile) = all.GetAt(i)?.cast::<VpnPlugInProfile>() {
                if profile.VpnPluginPackageFamilyName()? == family {
                    ours.push(profile);
                }
            }
        }

        self.busy.set(true);
        let result = self.fill_selector(&ours, select);
        self.busy.set(false);
        *self.profiles.borrow_mut() = ours;
        result?;
        self.on_select()
    }

    fn fill_selector(&self, profiles: &[VpnPlugInProfile], select: Option<&str>) -> Result<()> {
        let items = self.c.selector.Items()?;
        items.Clear()?;

        let mut selected = if profiles.is_empty() { -1 } else { 0 };
        for (i, profile) in profiles.iter().enumerate() {
            let name = profile.ProfileName()?;
            if select == Some(name.to_string_lossy().as_str()) {
                selected = i as i32;
            }
            items.Append(PropertyValue::CreateString(name)?)?;
        }
        self.c.selector.SetSelectedIndex(selected)
    }

    /// The Windows profile currently being edited, if there is one.
    fn selected(&self) -> Result<Option<VpnPlugInProfile>> {
        let index = self.c.selector.SelectedIndex()?;
        Ok(usize::try_from(index)
            .ok()
            .and_then(|i| self.profiles.borrow().get(i).cloned()))
    }

    fn on_select(&self) -> Result<()> {
        let existing = self.selected()?;
        let enabled = existing.is_some();
        self.c.editor.SetVisibility(if enabled {
            Visibility::Visible
        } else {
            Visibility::Collapsed
        })?;
        self.c.copy_ps.SetIsEnabled(enabled)?;

        // Clear first: `form_from` may leave a warning in the status line.
        self.set_status("")?;
        match existing {
            None => {
                self.write_form(&ProfileForm::default())?;
                self.set_status(NO_PROFILES)
            }
            Some(profile) => {
                let form = self.form_from(&profile)?;
                self.write_form(&form)
            }
        }
    }

    /// The server host stored in the Windows profile (empty if none).
    fn server_of(&self, profile: &VpnPlugInProfile) -> Result<String> {
        let uris = profile.ServerUris()?;
        if uris.Size()? == 0 {
            return Ok(String::new());
        }
        Ok(server_from_uri_host(
            &uris.GetAt(0)?.Host()?.to_string_lossy(),
        ))
    }

    fn form_from(&self, profile: &VpnPlugInProfile) -> Result<ProfileForm> {
        let name = profile.ProfileName()?.to_string_lossy();
        let server = self.server_of(profile)?;

        match WireGuardConfig::from_xml(&profile.CustomConfiguration()?.to_string_lossy()) {
            Ok(config) => Ok(ProfileForm::from_profile(&Profile {
                name,
                server,
                config,
            })),
            Err(err) => {
                self.set_status(&format!(
                    "This profile has no valid WireGuard settings yet ({err}). \
                     Fill in the fields and copy the PowerShell command."
                ))?;
                Ok(ProfileForm {
                    name,
                    server,
                    ..ProfileForm::default()
                })
            }
        }
    }

    fn read_form(&self) -> Result<ProfileForm> {
        let c = &self.c;
        Ok(ProfileForm {
            name: c.name.Text()?.to_string_lossy(),
            server: c.server.Text()?.to_string_lossy(),
            port: c.port.Text()?.to_string_lossy(),
            private_key: c.private_key.Password()?.to_string_lossy(),
            address: c.address.Text()?.to_string_lossy(),
            dns: c.dns.Text()?.to_string_lossy(),
            search_domains: c.search_domains.Text()?.to_string_lossy(),
            mtu: c.mtu.Text()?.to_string_lossy(),
            public_key: c.public_key.Text()?.to_string_lossy(),
            preshared_key: c.preshared_key.Password()?.to_string_lossy(),
            allowed_ips: c.allowed_ips.Text()?.to_string_lossy(),
            excluded_ips: c.excluded_ips.Text()?.to_string_lossy(),
            persistent_keepalive: c.keepalive.Text()?.to_string_lossy(),
        })
    }

    fn write_form(&self, form: &ProfileForm) -> Result<()> {
        let c = &self.c;
        c.name.SetText(form.name.as_str())?;
        c.server.SetText(form.server.as_str())?;
        c.port.SetText(form.port.as_str())?;
        c.private_key.SetPassword(form.private_key.as_str())?;
        c.address.SetText(form.address.as_str())?;
        c.dns.SetText(form.dns.as_str())?;
        c.search_domains.SetText(form.search_domains.as_str())?;
        c.mtu.SetText(form.mtu.as_str())?;
        c.public_key.SetText(form.public_key.as_str())?;
        c.preshared_key.SetPassword(form.preshared_key.as_str())?;
        c.allowed_ips.SetText(form.allowed_ips.as_str())?;
        c.excluded_ips.SetText(form.excluded_ips.as_str())?;
        c.keepalive.SetText(form.persistent_keepalive.as_str())
    }

    /// Put a `Set-VpnConnection` command for the current form on the clipboard.
    fn copy_powershell(&self) -> Result<()> {
        let profile = match self.read_form()?.to_profile() {
            Ok(profile) => profile,
            Err(err) => return self.set_status(&err.to_string()),
        };
        match profile.powershell_command() {
            Ok(command) => {
                copy_to_clipboard(&command)?;
                self.set_status("PowerShell command copied. Paste it into a PowerShell window.")
            }
            Err(err) => self.set_status(&err.to_string()),
        }
    }

    fn load_conf(self: &Rc<Self>) -> Result<()> {
        self.set_status("Choose a .conf file to load.")?;
        let dispatcher = self.c.status.Dispatcher()?;
        let picker = FileOpenPicker::new()?;
        picker
            .FileTypeFilter()?
            .Append(windows::core::HSTRING::from(".conf"))?;

        let this = self.clone();
        picker.PickSingleFileAsync()?.SetCompleted(
            AsyncOperationCompletedHandler::<StorageFile>::new(move |operation, status| {
                if status == AsyncStatus::Canceled {
                    return Ok(());
                }
                let Some(operation) = operation.as_ref() else {
                    this.dispatch_report(
                        &dispatcher,
                        this.set_status("File picker did not return a result."),
                    )?;
                    return Ok(());
                };
                let file = match operation.GetResults() {
                    Ok(file) => file,
                    Err(err) if err.code().0 == 0 => return Ok(()),
                    Err(err) => {
                        this.dispatch_report(&dispatcher, Err(err))?;
                        return Ok(());
                    }
                };
                let read = match FileIO::ReadTextAsync(&file) {
                    Ok(read) => read,
                    Err(err) => {
                        this.dispatch_report(&dispatcher, Err(err))?;
                        return Ok(());
                    }
                };
                let this = this.clone();
                let dispatcher = dispatcher.clone();
                read.SetCompleted(AsyncOperationCompletedHandler::<HSTRING>::new(
                    move |operation, status| {
                        if status == AsyncStatus::Canceled {
                            return Ok(());
                        }
                        let result = match operation.as_ref() {
                            Some(operation) => match operation.GetResults() {
                                Ok(text) => {
                                    let this = this.clone();
                                    dispatcher.RunAsync(
                                        CoreDispatcherPriority::Normal,
                                        DispatchedHandler::new(move || {
                                            this.report(this.apply_conf(&text.to_string_lossy()));
                                            Ok(())
                                        }),
                                    )?;
                                    return Ok(());
                                }
                                Err(err) if err.code().0 == 0 => Ok(()),
                                Err(err) => Err(err),
                            },
                            None => this.set_status("Could not read the selected file."),
                        };
                        this.dispatch_report(&dispatcher, result)?;
                        Ok(())
                    },
                ))?;
                Ok(())
            }),
        )
    }

    fn apply_conf(&self, text: &str) -> Result<()> {
        let imported = match parse_wg_quick(text) {
            Ok(imported) => imported,
            Err(err) => return self.set_status(&format!("Import failed: {err}")),
        };

        let current = self.read_form()?;
        let profile = Profile {
            name: current.name,
            server: imported
                .server
                .unwrap_or_else(|| current.server.trim().to_owned()),
            config: imported.config,
        };
        self.write_form(&ProfileForm::from_profile(&profile))?;
        self.set_status("Configuration loaded. Copy the PowerShell command to apply it.")
    }

    fn dispatch_report(
        self: &Rc<Self>,
        dispatcher: &CoreDispatcher,
        result: Result<()>,
    ) -> Result<()> {
        let this = self.clone();
        let mut result = Some(result);
        dispatcher.RunAsync(
            CoreDispatcherPriority::Normal,
            DispatchedHandler::new(move || {
                if let Some(result) = result.take() {
                    this.report(result);
                }
                Ok(())
            }),
        )?;
        Ok(())
    }

    /// Re-read the profile list, e.g. after adding one in Windows Settings.
    fn reload(&self) -> Result<()> {
        let name = match self.selected()? {
            Some(profile) => Some(profile.ProfileName()?.to_string_lossy()),
            None => None,
        };
        self.refresh(name.as_deref())
    }
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    let package = DataPackage::new()?;
    package.SetText(text)?;
    Clipboard::SetContent(&package)?;
    // Keep the text available after the app is closed.
    Clipboard::Flush()
}
