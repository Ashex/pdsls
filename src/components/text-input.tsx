export interface TextInputProps {
  ref?: HTMLInputElement;
  class?: string;
  id?: string;
  type?: "text" | "email" | "password" | "search" | "tel" | "url";
  name?: string;
  required?: boolean;
  disabled?: boolean;
  placeholder?: string;
  spellcheck?: boolean;
  value?: string | string[];
  onInput?: (ev: InputEvent & { currentTarget: HTMLInputElement }) => void;
}

export const TextInput = (props: TextInputProps) => {
  return (
    <input
      type={props.type ?? "text"}
      id={props.id}
      name={props.name}
      value={props.value ?? ""}
      ref={props.ref}
      spellcheck={props.spellcheck ?? false}
      placeholder={props.placeholder}
      disabled={props.disabled}
      required={props.required}
      class={
        "dark:bg-dark-100 bg-light-100 rounded-lg border border-gray-400 px-2 py-1 focus:outline-none focus:ring-1 focus:ring-gray-300 " +
        props.class
      }
      onInput={props.onInput}
    />
  );
};
