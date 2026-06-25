import { PiXLogoBold } from "react-icons/pi";
import {
  FaFacebookF,
  FaLinkedinIn,
  FaYoutube,
  FaInstagram,
  FaPhoneAlt,
  FaFax,
} from "react-icons/fa";
import { MdEmail, MdLocationOn } from "react-icons/md";

const Footer = () => {
  return (
    <footer className="bg-[#1e293b] text-gray-300 text-sm">
      {/* Main Footer Content */}
      <div className="max-w-7xl mx-auto px-6 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-8">
          {/* Company Info + Social */}
          <div className="lg:col-span-1">
            <div className="mb-4">
              <img
                src="https://cdn-labgd.nitrocdn.com/DgsEbCQFApREClXUXMwcDAPWJfHtBIby/assets/images/optimized/rev-df5b6d7/www.cloudthat.com/wp-content/themes/masterstudy-child/newfiles/images/logo.png"
                alt="CloudThat Logo"
                className="h-8 mb-4"
              />
            </div>
            <p className="text-gray-400 text-xs leading-relaxed mb-4">
              World's best Cloud Training and Cloud Consulting Services company,
              offering expert solutions in Cloud, DevOps, AI &amp; ML, IoT, Data
              Analytics, and Cloud Security for midsize and enterprise clients
              across the globe.
            </p>
            <div className="flex gap-2">
              <a
                href="https://www.facebook.com/cloudthat"
                target="_blank"
                rel="noopener noreferrer"
                className="w-8 h-8 flex items-center justify-center rounded-full bg-[#3b5998] text-white hover:opacity-80 transition-opacity"
                aria-label="Facebook"
              >
                <FaFacebookF className="text-xs" />
              </a>
              <a
                href="https://www.youtube.com/user/cloudthat"
                target="_blank"
                rel="noopener noreferrer"
                className="w-8 h-8 flex items-center justify-center rounded-full bg-[#ff0000] text-white hover:opacity-80 transition-opacity"
                aria-label="YouTube"
              >
                <FaYoutube className="text-xs" />
              </a>
              <a
                href="https://x.com/cloudthat"
                target="_blank"
                rel="noopener noreferrer"
                className="w-8 h-8 flex items-center justify-center rounded-full bg-[#1da1f2] text-white hover:opacity-80 transition-opacity"
                aria-label="X (Twitter)"
              >
                <PiXLogoBold className="text-xs" />
              </a>
              <a
                href="https://www.instagram.com/cloudthat/"
                target="_blank"
                rel="noopener noreferrer"
                className="w-8 h-8 flex items-center justify-center rounded-full bg-gradient-to-tr from-[#f9ce34] via-[#ee2a7b] to-[#6228d7] text-white hover:opacity-80 transition-opacity"
                aria-label="Instagram"
              >
                <FaInstagram className="text-xs" />
              </a>
              <a
                href="https://www.linkedin.com/company/cloudthat"
                target="_blank"
                rel="noopener noreferrer"
                className="w-8 h-8 flex items-center justify-center rounded-full bg-[#0077b5] text-white hover:opacity-80 transition-opacity"
                aria-label="LinkedIn"
              >
                <FaLinkedinIn className="text-xs" />
              </a>
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="text-white font-semibold mb-4 text-sm">Quick links</h4>
            <ul className="space-y-2 text-xs">
              <li>
                <a href="https://www.cloudthat.com/training/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Cloud Computing Courses
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/corporate-training" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Corporate Training
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/consulting/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Cloud Consulting
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/cloud-and-devops-expert-program/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Job Assistance Program
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/calendar/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Training calendar
                </a>
              </li>
              <li>
                <a href="https://testprep.cloudthat.com/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Test Prep
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/aws-mastery-pass" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  AWS Mastery Pass
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/azure-mastery-pass/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Azure Mastery Pass
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/devops-mastery-pass" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  DevOps Mastery Pass
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/hire-from-us" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Hire From Us
                </a>
              </li>
            </ul>
          </div>

          {/* Categories */}
          <div>
            <h4 className="text-white font-semibold mb-4 text-sm">Categories</h4>
            <ul className="space-y-2 text-xs">
              <li>
                <a href="https://www.cloudthat.com/training/ai-machine-learning-certification-course" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  AI &amp; ML Courses
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/aws/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  AWS Certifications and Training
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/azure/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Microsoft Azure Certifications
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/devops/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  DevOps Certifications
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/google-cloud-certification" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  GCP Certifications and Trainings
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/microsoftdynamics/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Microsoft Dynamics 365 Certifications
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/microsoft-security/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Microsoft Security Certifications
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/modernworkplace/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Modern Workplace Trainings
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/power-platform/pl-300-microsoft-power-bi-data-analyst-training" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Power BI Course
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/power-platform" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Power Platform Certification
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/training/vmware" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  VMware Certifications
                </a>
              </li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h4 className="text-white font-semibold mb-4 text-sm">Resources</h4>
            <ul className="space-y-2 text-xs">
              <li>
                <a href="https://www.cloudthat.com/resources/blogs" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Blogs
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/resources/news-events" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  News and Events
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/resources/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Case Study
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/resources/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  E-Book
                </a>
              </li>
              <li>
                <a href="https://www.cloudthat.com/resources/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-white transition-colors">
                  Webinars
                </a>
              </li>
            </ul>
          </div>

          {/* Contact */}
          <div>
            <h4 className="text-white font-semibold mb-4 text-sm">Contact</h4>
            <ul className="space-y-3 text-xs">
              <li className="flex items-start gap-2">
                <MdLocationOn className="text-base flex-shrink-0 mt-0.5 text-gray-400" />
                <a
                  href="https://g.page/CloudThat?share"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  102, 4th B Cross, 5th Block Koramangala Industrial Area,
                  Bangalore, Karnataka - 560095
                </a>
              </li>
              <li className="flex items-center gap-2">
                <MdEmail className="text-base flex-shrink-0 text-gray-400" />
                <a
                  href="mailto:sales@cloudthat.com"
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  sales@cloudthat.com
                </a>
              </li>
            </ul>

            {/* Certification Badges */}
            {/* <div className="mt-4 grid grid-cols-3 gap-3">
    
              <div className="w-14 h-14 rounded-full bg-white flex items-center justify-center p-1">
                <div className="text-center leading-none">
                  <span className="text-[7px] font-bold text-blue-600 block">CMMI</span>
                  <span className="text-[5px] text-gray-600 block">MATURITY LEVEL</span>
                  <span className="text-sm font-bold text-blue-700 block">5</span>
                </div>
              </div>
          
              <div className="w-14 h-14 rounded-full border-[3px] border-yellow-600 bg-gradient-to-b from-yellow-100 to-yellow-200 flex items-center justify-center">
                <div className="text-center leading-tight">
                  <span className="text-[5px] font-semibold text-yellow-800 block">CERTIFIED</span>
                  <span className="text-[8px] font-bold text-yellow-900 block">ISO</span>
                  <span className="text-[8px] font-bold text-yellow-900 block">27001</span>
                </div>
              </div>
           
              <div className="w-14 h-14 rounded-full border-[3px] border-yellow-600 bg-gradient-to-b from-gray-800 to-gray-900 flex items-center justify-center">
                <div className="text-center leading-tight">
                  <span className="text-[5px] font-semibold text-yellow-400 block">CERTIFIED</span>
                  <span className="text-[9px] font-bold text-yellow-400 block">ISO</span>
                  <span className="text-[8px] font-bold text-yellow-400 block">15010</span>
                </div>
              </div>
           
              <div className="w-14 h-14 rounded-full border-[3px] border-yellow-500 bg-gradient-to-b from-gray-800 to-gray-900 flex items-center justify-center">
                <div className="text-center leading-tight">
                  <span className="text-[5px] font-semibold text-yellow-400 block">★ ★ ★</span>
                  <span className="text-[9px] font-bold text-white block">ISO</span>
                  <span className="text-[8px] font-bold text-white block">27701</span>
                </div>
              </div>
            </div> */}
          </div>
        </div>
      </div>

      {/* Office Locations */}
      <div className="border-t border-gray-700">
        <div className="max-w-7xl mx-auto px-6 py-8 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-6">
          <div>
            <h5 className="text-white font-semibold text-xs mb-2">India – Headquarter</h5>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              102, 4th B Cross,<br />
              5th Block Koramangala Industrial Area,<br />
              Bangalore, Karnataka - 560095.
            </p>
          </div>
          <div>
            <h5 className="text-white font-semibold text-xs mb-2">East India and SAARC</h5>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              RDB Boulevard, Level 8, Plot K-1,<br />
              Block EP &amp; GP, Salt Lake City,<br />
              Sector V, Kolkata – 700 091.
            </p>
          </div>
          <div>
            <h5 className="text-white font-semibold text-xs mb-2">USA</h5>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              CLOUDTHAT AMERICAS LTD, 1916 Pike Place, Seattle,<br />
              WA 98101
            </p>
            <p className="text-[11px] text-gray-400 mt-2 flex items-center gap-1">
              <FaPhoneAlt className="text-[9px]" />
              <a href="tel:+18555588830" className="hover:text-white transition-colors">+1 855 558 8830</a>
            </p>
            <p className="text-[11px] text-gray-400 flex items-center gap-1">
              <FaFax className="text-[9px]" />
              <span>Fax: 206 737-9006</span>
            </p>
          </div>
          <div>
            <h5 className="text-white font-semibold text-xs mb-2">UK</h5>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              7B Popin Business Centre South<br />
              Way Wembley<br />
              Middlesex – HA9 0HF.
            </p>
            <p className="text-[11px] text-gray-400 mt-2 flex items-center gap-1">
              <FaPhoneAlt className="text-[9px]" />
              <a href="tel:+18555588830" className="hover:text-white transition-colors">+1 855 558 8830</a>
            </p>
          </div>
          <div>
            <h5 className="text-white font-semibold text-xs mb-2">Bangladesh</h5>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              House #107,<br />
              Road #13,<br />
              Block #E,<br />
              Banani,<br />
              Dhaka – 1213
            </p>
          </div>
          <div>
            <h5 className="text-white font-semibold text-xs mb-2">Ahmedabad</h5>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              D-509, 5th floor, The First,<br />
              behind ITC Narmada Hotel,<br />
              Vastrapur,<br />
              Ahmedabad - 380015
            </p>
          </div>
        </div>
      </div>

      {/* Copyright Bar */}
      <div className="border-t border-gray-700 bg-[#0f172a]">
        <div className="max-w-7xl mx-auto px-6 py-4 text-center text-[11px] text-gray-500">
          <p>
            ©COPYRIGHT 2025 CLOUDTHAT TECHNOLOGIES PRIVATE LIMITED · ALL RIGHTS RESERVED ·{" "}
            <a href="https://www.cloudthat.com/courses/privacy-policy/" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">
              PRIVACY POLICY
            </a>{" "}·{" "}
            <a href="https://www.cloudthat.com/courses/terms-of-use/" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">
              TERMS OF USE
            </a>{" "}·{" "}
            <a href="https://www.cloudthat.com/courses/disclaimer/" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">
              DISCLAIMER
            </a>{" "}·{" "}
            <a href="https://www.cloudthat.com/cancellation-and-refund-policy/" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">
              CANCELLATION AND REFUND
            </a>
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
