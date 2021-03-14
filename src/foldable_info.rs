use yew::prelude::*;

#[derive(Properties, Clone)]
pub struct FoldableInfoProperties {
    pub title: String,
    pub children: Children,
}

pub struct FoldableInfo {
    props: FoldableInfoProperties,
    link: ComponentLink<Self>,
    open: bool,
}

impl Component for FoldableInfo {
    type Message = ();
    type Properties = FoldableInfoProperties;

    fn create(props: Self::Properties, link: ComponentLink<Self>) -> Self {
        FoldableInfo {
            props,
            link,
            open: false,
        }
    }

    fn update(&mut self, _msg: Self::Message) -> ShouldRender {
        self.open = !self.open;
        true
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        true
    }

    fn view(&self) -> Html {
        html! {
            <div class="foldable_info">
                <h3 onclick=self.link.callback(|_| ())>{&self.props.title}{if self.open {" [reduce]"} else {" [expand]"}}</h3>
                {
                    if self.open {
                        html! {
                            <p>
                                {self.props.children.clone()}
                            </p>
                        }
                    } else {
                        html! {}
                    }
                }
            </div>
        }
    }
}