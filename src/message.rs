use yew::prelude::*;

#[derive(Properties, Clone)]
pub struct MessageProperties {
    pub level: String,
    pub children: Children,
}

pub struct Message {
    props: MessageProperties,
}

impl Component for Message {
    type Message = ();
    type Properties = MessageProperties;

    fn create(props: Self::Properties, _link: ComponentLink<Self>) -> Self {
        Message { props }
    }

    fn update(&mut self, _msg: Self::Message) -> ShouldRender {
        false
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        true
    }

    fn view(&self) -> Html {
        match self.props.level.as_str() {
            "success" => {
                html! {
                    <p class="success_message">
                        <b>{"Success: "}</b>
                        {self.props.children.clone()}
                    </p>
                }
            }
            "info" => {
                html! {
                    <p class="info_message">
                        <b>{"Info: "}</b>
                        {self.props.children.clone()}
                    </p>
                }
            }
            "warning" => {
                html! {
                    <p class="warning_message">
                        <b>{"Warning: "}</b>
                        {self.props.children.clone()}
                    </p>
                }
            }
            "danger" => {
                html! {
                    <p class="danger_message">
                        <b>{"Danger: "}</b>
                        {self.props.children.clone()}
                    </p>
                }
            }
            "error" => {
                html! {
                    <p class="danger_message">
                        <b>{"Danger: "}</b>
                        {self.props.children.clone()}
                    </p>
                }
            }
            level => {
                html! {
                    <p class="info_message">
                        <b>{format!("{}: ", level)}</b>
                        {self.props.children.clone()}
                    </p>
                }
            }
        }
    }
}
