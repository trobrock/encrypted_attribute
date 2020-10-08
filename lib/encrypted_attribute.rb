require "encrypted_attribute/version"

require 'active_support/concern'
require 'active_support/message_encryptor'

module EncryptedAttribute
  extend ActiveSupport::Concern

  class_methods do
    def attr_encrypted(attr)
      define_method(attr) do
        value = instance_variable_get("@#{attr}")
        return value if value

        raw_value = public_send("encrypted_#{attr}".to_sym)
        return nil unless raw_value

        instance_variable_set "@#{attr}", encryptor.decrypt_and_verify(raw_value)
      end

      define_method("#{attr}=") do |new_value|
        value = encryptor.encrypt_and_sign(new_value)
        instance_variable_set("@#{attr}", new_value)
        public_send("encrypted_#{attr}=", value)
      end
    end
  end

  private

  def encryptor
    @encryptor = ActiveSupport::MessageEncryptor.new(encryptor_key)
  end

  def encryptor_key
    ENV['RAILS_MASTER_KEY'] || File.read(Rails.application.config.credentials.key_path)
  end
end
