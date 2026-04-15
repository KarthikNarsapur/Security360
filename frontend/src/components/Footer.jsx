import React from "react";
import { PiXLogoBold } from "react-icons/pi";
import { FaFacebookF, FaLinkedinIn, FaYoutube } from "react-icons/fa";

const Footer = () => {
  return (
    <div className="items-center bg-white p-8 text-center text-gray-300 font-semibold dark:bg-gray-300 dark:text-gray-400">
      <div className="text-sm">
        Privacy Policy | Trust | Legal | Security | GDPR | Patents | Trademarks
        | Your Privacy Choices
      </div>
      <div className="flex justify-center my-4 text-gray-400 dark:text-gray-500">
        <PiXLogoBold />
        &nbsp;&nbsp;
        <FaFacebookF />
        &nbsp;&nbsp;
        <FaLinkedinIn />
        &nbsp;&nbsp;
        <FaYoutube />
      </div>
      <div>©COPYRIGHT 2025 Security360 · ALL RIGHTS RESERVED</div>
    </div>
  );
};

export default Footer;
