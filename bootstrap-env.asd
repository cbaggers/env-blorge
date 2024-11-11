;;;; bootstrap-env.asd

(asdf:defsystem #:bootstrap-env
  :description "Describe bootstrap-env here"
  :author "Your Name <your.name@example.com>"
  :license  "Specify license here"
  :version "0.0.1"
  :serial t
  :depends-on (:binary-structures :memory-regions :cffi)
  :components ((:file "package")
               (:file "bootstrap-env")))
