'use client';

import { useState } from 'react';
import { ChevronDown } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

interface AccordionItemProps {
  icon: LucideIcon;
  title: string;
  subtitle: string;
  content: React.ReactNode;
  defaultOpen?: boolean;
}

function AccordionItem({
  icon: Icon,
  title,
  subtitle,
  content,
  defaultOpen = false,
}: AccordionItemProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div
      className={`
        rounded-lg border backdrop-blur-sm transition-all duration-300
        ${
          isOpen
            ? 'border-primary-400 bg-primary-800/60'
            : 'border-primary-700 bg-primary-800/30 hover:border-primary-600 hover:bg-primary-800/50'
        }
      `}
    >
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex w-full items-start gap-3 p-4 text-left active:bg-primary-800/70 sm:gap-4 md:p-6"
      >
        <Icon
          className={`h-6 w-6 flex-shrink-0 transition-colors duration-300 sm:h-8 sm:w-8 ${
            isOpen ? 'text-primary-300' : 'text-primary-400'
          }`}
        />
        <div className="flex-1">
          <h3 className="mb-1 text-base font-semibold text-white sm:mb-2 md:text-lg">{title}</h3>
          <p className="text-xs text-primary-300 sm:text-sm">{subtitle}</p>
        </div>
        <ChevronDown
          className={`h-5 w-5 flex-shrink-0 text-primary-400 transition-transform duration-300 sm:h-6 sm:w-6 ${
            isOpen ? 'rotate-180' : ''
          }`}
        />
      </button>

      <div
        className={`
          overflow-hidden transition-all duration-300 ease-in-out
          ${isOpen ? 'max-h-[600px] opacity-100 md:max-h-[1000px]' : 'max-h-0 opacity-0'}
        `}
      >
        <div className="border-t border-primary-700 px-4 pb-4 pt-3 sm:px-6 sm:pb-6 sm:pt-4">
          <div className="pl-0 text-sm leading-relaxed text-primary-200 md:pl-12 md:text-base">
            {content}
          </div>
        </div>
      </div>
    </div>
  );
}

interface TechnicalAccordionProps {
  items: Array<{
    icon: LucideIcon;
    title: string;
    subtitle: string;
    content: React.ReactNode;
  }>;
}

export function TechnicalAccordion({ items }: TechnicalAccordionProps) {
  return (
    <div className="space-y-3 md:space-y-4">
      {items.map((item, index) => (
        <AccordionItem
          key={item.title}
          icon={item.icon}
          title={item.title}
          subtitle={item.subtitle}
          content={item.content}
          defaultOpen={index === 0} // First item open by default
        />
      ))}
    </div>
  );
}
