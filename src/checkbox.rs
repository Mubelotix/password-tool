use yew::prelude::*;

pub struct Checkbox<T: Clone + Default + 'static> {
    link: ComponentLink<Self>,
    callback: Callback<(bool, T)>,
    checked: bool,
    label: String,
    id: T,
}

impl<T: Clone + Default> Checkbox<T> {
    pub fn is_checked(&self) -> bool {
        self.checked
    }
}

impl<T: Clone + Default> Component for Checkbox<T> {
    type Message = ();
    type Properties = CheckboxProp<T>;

    fn create(properties: Self::Properties, link: ComponentLink<Self>) -> Self {
        Checkbox {
            link,
            checked: properties.checked,
            label: properties.label,
            id: properties.id,
            callback: properties.onchange
        }
    }

    fn update(&mut self, _: ()) -> bool {
        self.checked = !self.checked;
        self.callback.emit((self.checked, self.id.clone()));

        false
    }

    fn view(&self) -> Html {
        html! {
            <div>
                <label class="label-switch">
                    <div class="toggle-switch">
                        <input class="toggle-state-switch" type="checkbox" name="check" value="check" onchange=self.link.callback(|_| ()) checked=self.checked/>
                        <div class="toggle-inner-switch">
                        <div class="indicator-switch"></div>
                        </div>
                        <div class="active-bg-switch"></div>
                    </div>
                    <div class="label-text-switch">{&self.label}</div>
                </label>
                <br/>
            </div>
        }
    }
}

#[derive(Clone, Properties)]
pub struct CheckboxProp<T: Clone + Default> {
    #[prop_or_default]
    pub label: String,
    #[prop_or_default]
    pub id: T,
    #[prop_or(false)]
    pub checked: bool,
    #[prop_or_default]
    pub onchange: Callback<(bool, T)>,
}