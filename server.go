package main

type Server interface {
    ListenAndServe() error
}

