"use client";

import { useState } from "react";
import { Form, Input, Select, Checkbox, Button, Spin } from "antd";
import { User, Mail, Phone, MessageSquare } from "lucide-react";
import { notifyError, notifySuccess } from "./Notification";

const { TextArea } = Input;

export default function ContactForm() {
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();

  const handleSubmit = async (values) => {
    setLoading(true);

    const backend_url = process.env.REACT_APP_BACKEND_URL;

    try {
      // Prepare payload for backend
      const payload = {
        name: values.name,
        email: values.email,
        phone: values.phone,
        interest: values.interest,
        company: values.company || "",
        message: values.message || "",
        consent: values.consent || false,
      };

      // Call backend API
      const response = await fetch(`${backend_url}/api/contact-us`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const apiResponse = await response.json();

      if (apiResponse?.status === "ok") {
        notifySuccess("Thank you! We will get back to you within 24 hours.");
        form.resetFields(); // Reset AntD form fields
      } else {
        notifyError(apiResponse?.message || "Failed to submit form");
      }
    } catch (error) {
      console.error("Error submitting contact form:", error);
      notifyError("Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const validatePhone = (_, value) => {
    if (!value) return Promise.resolve();
    if (!/^\d{10}$/.test(value))
      return Promise.reject("Enter a valid 10-digit number");
    return Promise.resolve();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 p-6">
      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-12 items-start">
        {/* Left side */}
        <div className="space-y-8">
          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="w-16 h-16 relative">
              <div className="absolute inset-0 bg-gradient-to-br from-indigo-500 to-indigo-600 rounded-full"></div>
              <div className="absolute top-2 left-2 w-12 h-12 bg-gradient-to-br from-purple-400 to-purple-500 rounded-full"></div>
            </div>
          </div>

          {/* Heading */}
          <div className="space-y-4">
            <h1 className="text-4xl lg:text-5xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent leading-tight">
              Got a Question on How We Can Assist You?
            </h1>
            <p className="text-lg text-slate-600 dark:text-slate-400 leading-relaxed">
              Drop us an Enquiry and we will get back to you with solutions for
              your query in next 24 hours
            </p>
          </div>

          {/* Contact Info */}
          <div className="space-y-4">
            {/* <div className="flex items-center gap-3 text-indigo-600 dark:text-indigo-400">
              <Phone className="w-5 h-5" />
              <span className="text-lg font-medium">+91 8880002200</span>
            </div> */}
            <div className="flex items-center gap-3 text-indigo-600 dark:text-indigo-400">
              <Mail className="w-5 h-5" />
              <span className="text-lg font-medium">
                consulting-marketing@cloudthat.com
              </span>
            </div>
          </div>
        </div>

        {/* Right side - Form */}
        <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-8 border border-indigo-100 dark:border-slate-700">
          <Form
            form={form}
            layout="vertical"
            onFinish={handleSubmit}
            initialValues={{ consent: false }}
            className="space-y-6"
          >
            {/* Name Field */}
            <Form.Item
              name="name"
              label="Name"
              rules={[{ required: true, message: "Name is required" }]}
            >
              <Input
                prefix={<User className="text-slate-400 w-5 h-5" />}
                placeholder="Enter your name"
                size="large"
              />
            </Form.Item>

            {/* Email Field */}
            <Form.Item
              name="email"
              label="Email Id"
              rules={[
                { required: true, message: "Email is required" },
                { type: "email", message: "Please enter a valid email" },
              ]}
            >
              <Input
                prefix={<Mail className="text-slate-400 w-5 h-5" />}
                placeholder="Enter your email"
                size="large"
              />
            </Form.Item>

            {/* Phone Field */}
            <Form.Item
              name="phone"
              label="Phone Number"
              rules={[
                { required: true, message: "Phone number is required" },
                { validator: validatePhone },
              ]}
            >
              <Input
                prefix={<Phone className="text-slate-400 w-5 h-5" />}
                placeholder="Enter 10-digit phone number"
                maxLength={10}
                size="large"
              />
            </Form.Item>

            {/* Interest Field */}
            {/* <Form.Item
              name="interest"
              label="I am Interested in"
              rules={[
                { required: true, message: "Please select your interest" },
              ]}
            >
              <Select placeholder="Select your interest" size="large">
                <Select.Option value="individual-training">
                  Individual Training
                </Select.Option>
                <Select.Option value="corporate-training">
                  Corporate Training
                </Select.Option>
                <Select.Option value="consulting">
                  Consulting Services
                </Select.Option>
                <Select.Option value="cloud-migration">
                  Cloud Migration
                </Select.Option>
                <Select.Option value="security-audit">
                  Security Audit
                </Select.Option>
              </Select>
            </Form.Item> */}

            {/* Company Field */}
            <Form.Item name="company" label="Company/Institute Name">
              <Input placeholder="Enter your company/institute" size="large" />
            </Form.Item>

            {/* Message Field */}
            <Form.Item name="message" label="Message">
              <TextArea
                prefix={<MessageSquare className="text-slate-400 w-5 h-5" />}
                rows={5}
                placeholder="Tell us about your requirements..."
                size="large"
              />
            </Form.Item>

            {/* Consent Checkbox */}
            <Form.Item
              name="consent"
              valuePropName="checked"
              rules={[
                {
                  validator: (_, value) =>
                    value
                      ? Promise.resolve()
                      : Promise.reject("Please agree to be contacted"),
                },
              ]}
            >
              <Checkbox>
                By checking, I agree to be contacted by CloudThat through SMS,
                WhatsApp & other means.
              </Checkbox>
            </Form.Item>

            {/* Submit Button */}
            <Form.Item>
              <Button
                type="primary"
                htmlType="submit"
                size="large"
                className={`btn-primary ${
                  loading ? "btn-primary-loading" : ""
                }`}
                disabled={loading}
                loading={loading}
              >
                {loading ? <Spin /> : "Submit"}
              </Button>
            </Form.Item>
          </Form>
        </div>
      </div>
    </div>
  );
}
