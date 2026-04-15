import { message } from "antd";

message.config({
  top: 20,
  duration: 5,
  maxCount: 6,
});

const notifyError = (errorText) => {
  message.error({
    content: errorText,
    style: {
      marginTop: "10px",
    },
  });
};

const notifySuccess = (successText) => {
  message.success({
    content: successText,
    style: {
      marginTop: "10px",
    },
  });
};

const notifyInfo = (infoText) => {
  message.info({
    content: infoText,
    style: {
      marginTop: "10px",
    },
  });
};

const notifyRedirectToContact = (navigate, seconds = 5) => {
  let remaining = seconds;
  const key = "redirect_to_contact"; // unique key for updating the same toast

  // Show initial message
  message.info({
    content: `Redirecting you to Contact Us in ${remaining} second${
      remaining > 1 ? "s" : ""
    }...`,
    style: { marginTop: "10px" },
    key,
    duration: 0,
  });

  const interval = setInterval(() => {
    remaining -= 1;

    if (remaining > 0) {
      // Update the same message
      message.info({
        content: `Redirecting you to Contact Us in ${remaining} second${
          remaining > 1 ? "s" : ""
        }...`,
        key,
        style: { marginTop: "10px" },
        duration: 0,
      });
    } else {
      clearInterval(interval);
      message.destroy(key); // remove the toast
      navigate("/contact-us"); // redirect
    }
  }, 1000);
};

export { notifyError, notifySuccess, notifyInfo, notifyRedirectToContact };
