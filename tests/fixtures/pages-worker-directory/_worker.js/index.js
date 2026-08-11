import { message } from "./chunks/message.mjs";

export default {
  fetch() {
    return new Response(message);
  },
};
