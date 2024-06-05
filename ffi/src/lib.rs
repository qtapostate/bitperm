use neon::context::FunctionContext;
use neon::prelude::*;
#[neon::main]
pub fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("createScope", create_scope)?;
    Ok(())
}

fn create_scope(mut cx: FunctionContext) -> JsResult<JsObject> {
    let name: Handle<JsValue> = cx.argument(0)?;

    let obj = cx.empty_object();

    obj.set(&mut cx, "name", name)?;

    Ok(obj)
}